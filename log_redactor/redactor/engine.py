"""脱敏引擎：策略编译、记录遍历、动作执行与残留风险扫描。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .crypto import MasterKey, deterministic_token, key_fingerprint
from .detectors import scan, _merge_spans
from .models import (
    AuditEntry,
    RiskFinding,
    Rule,
    RunResult,
    RunStats,
    Strategy,
)

MAX_RISK_FINDINGS = 500
_TOKEN_PREFIX = "T-"  # 与 detectors 协调：自定义令牌不会被内置识别器再次命中


def display_path(path: str) -> str:
    """内部路径（如 ``user.addrs[0].ip``）转成 ``$.user.addrs[0].ip``。"""
    if not path:
        return "$"
    return path if path.startswith("$") else ("$." + path if not path.startswith("[") else "$" + path)


# ---------- 路径通配 ----------


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """把 JSONPath 风格通配编译为正则。

    * ``**`` 跨任意层级（含数组下标），``*`` 单段内通配，``?`` 单字符；
    * 可带 ``$`` 与前导点：``$.user.email`` 等价于 ``user.email``。
    """
    p = pattern
    if p.startswith("$"):
        p = p[1:]
    if p.startswith("."):
        p = p[1:]

    out: list[str] = ["^"]
    i = 0
    while i < len(p):
        ch = p[i]
        if ch == "*":
            if i + 1 < len(p) and p[i + 1] == "*":
                out.append(".*")
                i += 2
                if i < len(p) and p[i] == ".":
                    i += 1
            else:
                out.append(r"[^.\[\]]*")
                i += 1
        elif ch == "?":
            out.append(r"[^.\[\]]")
            i += 1
        elif ch == "[":
            close = p.find("]", i + 1)
            if close == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                inner = p[i + 1 : close]
                if inner == "*":
                    out.append(r"\[\d+\]")
                elif inner == "?":
                    out.append(r"\[\d\]")
                elif re.fullmatch(r"\d+", inner):
                    out.append(r"\[" + inner + r"\]")
                elif inner.startswith("*:") or (":" in inner):
                    # 形如 [*:1] 的切片不支持，按字面量处理
                    out.append(re.escape(p[i : close + 1]))
                else:
                    out.append(re.escape(p[i : close + 1]))
                i = close + 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


# ---------- 策略编译 ----------


@dataclass
class CompiledRule:
    rule: Rule
    path_res: list[re.Pattern[str]] = field(default_factory=list)
    key_names: set[str] = field(default_factory=set)
    key_glob_res: list[re.Pattern[str]] = field(default_factory=list)
    key_pat_res: list[re.Pattern[str]] = field(default_factory=list)
    value_pat_res: list[re.Pattern[str]] = field(default_factory=list)

    @property
    def is_field_rule(self) -> bool:
        return self.rule.match.has_field_dimension() and not self.rule.match.has_content_dimension()

    @property
    def is_content_rule(self) -> bool:
        return self.rule.match.has_content_dimension()

    def field_matches(self, path: str, key: str | None) -> bool:
        m = self.rule.match
        # 路径维度：任一 field_path 命中即可
        if m.field_paths and not any(rx.fullmatch(path) for rx in self.path_res):
            return False
        # 键名维度：key_names / key_globs / key_patterns 三者之间是 OR
        if any([m.key_names, m.key_globs, m.key_patterns]):
            key_hit = (
                (bool(m.key_names) and key in self.key_names)
                or (
                    bool(m.key_globs)
                    and key is not None
                    and any(rx.fullmatch(key) for rx in self.key_glob_res)
                )
                or (
                    bool(m.key_patterns)
                    and key is not None
                    and any(rx.search(key) for rx in self.key_pat_res)
                )
            )
            if not key_hit:
                return False
        return True


def compile_strategy(strategy: Strategy) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    for rule in strategy.rules:
        if not rule.enabled:
            continue
        m = rule.match
        compiled.append(
            CompiledRule(
                rule=rule,
                path_res=[glob_to_regex(p) for p in m.field_paths],
                key_names=set(m.key_names),
                key_glob_res=[glob_to_regex(g) for g in m.key_globs],
                key_pat_res=[re.compile(p) for p in m.key_patterns],
                value_pat_res=[re.compile(p) for p in m.value_patterns],
            )
        )
    return compiled


# ---------- 值动作 ----------


def _mask_whole(value: Any, char: str, prefix: int, suffix: int) -> Any:
    """整字段掩码，尽量保留数据类型与长度特征。"""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        text = str(value)
        digit_pos = [i for i, c in enumerate(text) if c.isdigit()]
        n = len(digit_pos)
        keep_pos = set(digit_pos[: min(prefix, n)]) | set(
            digit_pos[max(0, n - suffix) :]
        )
        masked = "".join(
            c if (not c.isdigit() or i in keep_pos) else "0"
            for i, c in enumerate(text)
        )
        return int(masked) if isinstance(value, int) else float(masked)
    text = str(value)
    if prefix + suffix >= len(text):
        return char * len(text)
    middle = max(1, len(text) - prefix - suffix)
    return text[:prefix] + char * middle + text[len(text) - suffix:] if suffix else (
        text[:prefix] + char * middle
    )


def _mask_span(text: str, start: int, end: int, char: str, prefix: int, suffix: int) -> str:
    chunk = text[start:end]
    kept_p = chunk[:prefix]
    kept_s = chunk[len(chunk) - suffix:] if suffix else ""
    middle_len = max(1, len(chunk) - prefix - suffix)
    replacement = kept_p + char * middle_len + kept_s
    return text[:start] + replacement + text[end:]


# ---------- 引擎 ----------


class RedactionEngine:
    def __init__(self, strategy: Strategy, key: MasterKey, is_ndjson: bool = False) -> None:
        self.strategy = strategy
        self.compiled = compile_strategy(strategy)
        self.field_rules = [c for c in self.compiled if c.is_field_rule]
        self.content_rules = [c for c in self.compiled if c.is_content_rule]
        self.key = key
        self.is_ndjson = is_ndjson
        self.audit: list[AuditEntry] = []
        self.risks: list[RiskFinding] = []
        self.fields_scanned = 0
        self.by_rule: dict[str, int] = {}
        self.by_action: dict[str, int] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        # (record_index, field_path)：被整字段规则处理过的叶子，
        # 残留风险扫描时整体跳过（掩码前缀可能形似原数据，如 z***@example.com）
        self._fully_handled: set[tuple[int, str]] = set()

    # -- token 缓存：同一命名空间下同一明文，整批恒等替身 --
    def _token(self, namespace: str, raw: str) -> str:
        cache_key = (namespace, raw)
        token = self._tokens.get(cache_key)
        if token is None:
            token = deterministic_token(self.key, namespace, raw)
            self._tokens[cache_key] = token
        return token

    def _record_audit(self, idx: int, path: str, key: str | None, cr: CompiledRule,
                      match_type: str, hit_by: list[str], occurrences: int = 1) -> None:
        self.audit.append(
            AuditEntry(
                record_index=idx,
                line_no=(idx + 1) if self.is_ndjson else None,
                field_path=display_path(path),
                key_name=key,
                rule_id=cr.rule.id,
                rule_name=cr.rule.name,
                action=cr.rule.action,
                match_type=match_type,  # type: ignore[arg-type]
                hit_by=hit_by,
                occurrences=occurrences,
            )
        )
        self.by_rule[cr.rule.id] = self.by_rule.get(cr.rule.id, 0) + 1
        self.by_action[cr.rule.action] = self.by_action.get(cr.rule.action, 0) + 1

    # -- 单个标量叶子 --
    def _apply_leaf(self, value: Any, idx: int, path: str, key: str | None) -> Any:
        self.fields_scanned += 1

        # 1) 整字段规则：按策略顺序第一个命中即生效
        for cr in self.field_rules:
            if cr.field_matches(path, key):
                self._record_audit(idx, path, key, cr, "field", ["field_match"])
                if path:
                    self._fully_handled.add((idx, path))
                return self._field_action(value, cr)

        # 2) 内容规则：仅对字符串值做片段替换
        if isinstance(value, str):
            return self._apply_content_rules(value, idx, path, key)
        return value

    def _field_action(self, value: Any, cr: CompiledRule) -> Any:
        action = cr.rule.action
        if action == "delete":
            return None
        if action == "mask":
            return _mask_whole(value, cr.rule.mask_char, cr.rule.keep_prefix, cr.rule.keep_suffix)
        # tokenize
        if isinstance(value, bool) or value is None:
            return value
        ns = cr.rule.token_namespace or cr.rule.id
        return self._token(ns, str(value))

    def _apply_content_rules(self, text: str, idx: int, path: str, key: str | None) -> str:
        # 候选区间按规则顺序贪心占位，重叠片段归先定义的规则
        taken: list[tuple[int, int]] = []

        def _free(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
            out: list[tuple[int, int]] = []
            for s, e in spans:
                cur_s = s
                for ts, te in sorted(taken):
                    if ts >= e:
                        break
                    if te <= cur_s:
                        continue
                    if ts <= cur_s < te:
                        cur_s = te
                if cur_s < e:
                    out.append((cur_s, e))
            return _merge_spans(out)

        jobs: list[tuple[CompiledRule, list[tuple[int, int]], list[str]]] = []
        for cr in self.content_rules:
            if cr.rule.match.has_field_dimension() and not cr.field_matches(path, key):
                continue
            candidates: list[tuple[int, int]] = []
            labels: list[str] = []
            for pat in cr.value_pat_res:
                spans = [(m.start(), m.end()) for m in pat.finditer(text)]
                if spans:
                    candidates.extend(spans)
                    labels.append(f"regex:{pat.pattern}")
            if cr.rule.match.detectors:
                found = scan(text, cr.rule.match.detectors)
                for det_name, spans in found.items():
                    candidates.extend(spans)
                    labels.append(f"detector:{det_name}")
            if not candidates:
                continue
            spans = _free(_merge_spans(candidates))
            if not spans:
                continue
            taken.extend(spans)
            jobs.append((cr, spans, labels))

        if not jobs:
            return text

        # 从后向前替换，避免位移；审计先到先写
        for cr, spans, labels in jobs:
            self._record_audit(
                idx, path, key, cr, "content", labels, occurrences=len(spans)
            )
        for cr, spans, _labels in reversed(jobs):
            for s, e in reversed(spans):
                if cr.rule.action == "delete":
                    text = text[:s] + text[e:]
                elif cr.rule.action == "mask":
                    text = _mask_span(text, s, e, cr.rule.mask_char,
                                      cr.rule.keep_prefix, cr.rule.keep_suffix)
                else:
                    ns = cr.rule.token_namespace or cr.rule.id
                    token = self._token(ns, text[s:e])
                    text = text[:s] + token + text[e:]
        return text

    # -- 递归遍历 --
    def _walk(self, node: Any, idx: int, path: str, key: str | None) -> Any:
        if isinstance(node, dict):
            return {
                k: self._walk(v, idx, f"{path}.{k}" if path else k, k)
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [
                self._walk(v, idx, f"{path}[{i}]", key)
                for i, v in enumerate(node)
            ]
        return self._apply_leaf(node, idx, path, key)

    # -- 残留风险扫描 --
    def _scan_risks(self, node: Any, idx: int, path: str) -> None:
        if len(self.risks) >= MAX_RISK_FINDINGS:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                self._scan_risks(v, idx, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                self._scan_risks(v, idx, f"{path}[{i}]")
        elif path and (idx, path) in self._fully_handled:
            return
        elif isinstance(node, str):
            found = scan(node, self.strategy.risk_detectors)
            for det_name, spans in found.items():
                for s, e in spans:
                    # 跳过本工具生成的确定性令牌，避免把替身误判为残留敏感内容
                    if node[s:e].startswith(_TOKEN_PREFIX):
                        continue
                    self.risks.append(
                        RiskFinding(
                            record_index=idx,
                            line_no=(idx + 1) if self.is_ndjson else None,
                            field_path=display_path(path),
                            detector=det_name,
                            length=e - s,
                        )
                    )
                    if len(self.risks) >= MAX_RISK_FINDINGS:
                        return

    def run(self, records: list[Any]) -> RunResult:
        out: list[Any] = []
        for idx, record in enumerate(records):
            if isinstance(record, (dict, list)):
                out.append(self._walk(record, idx, "", None))
            else:
                # 顶层标量日志：作为根叶子处理（规则可用 field_path "$"）
                self.fields_scanned += 1
                out.append(self._apply_leaf(record, idx, "", None))
        for idx, record in enumerate(out):
            self._scan_risks(record, idx, "")

        stats = RunStats(
            records_in=len(records),
            fields_scanned=self.fields_scanned,
            audit_entries=len(self.audit),
            risk_findings=len(self.risks),
            by_action=self.by_action,
            by_rule=self.by_rule,
        )
        return RunResult(
            records=out,
            audit=self.audit,
            risks=self.risks,
            stats=stats,
            needs_review=bool(self.risks),
            key_fingerprint=key_fingerprint(self.key),
        )


def run_strategy(strategy: Strategy, records: list[Any], key: MasterKey,
                 is_ndjson: bool = False) -> RunResult:
    return RedactionEngine(strategy, key, is_ndjson=is_ndjson).run(records)
