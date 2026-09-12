"""脱敏引擎：策略编译、记录遍历、内嵌结构解码、动作执行与残留风险扫描。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .crypto import (
    MasterKey,
    deterministic_number_token,
    deterministic_token,
    key_fingerprint,
)
from .detectors import scan, _merge_spans
from .embedded import (
    DecodeError,
    decode_json_string,
    encode_json_string,
    encode_query_value,
    json_expanded_bytes,
    parse_query_segments,
    query_expanded_bytes,
    render_segment,
    split_url_query,
)
from .models import (
    AuditEntry,
    DecodeIssue,
    EmbeddedDecoder,
    RiskFinding,
    Rule,
    RunResult,
    RunStats,
    Strategy,
)

MAX_RISK_FINDINGS = 500
MAX_DECODE_ISSUES = 500  # 与残留风险同口径的待复核原因上限
_TOKEN_PREFIX = "T-"  # 与 detectors 协调：自定义令牌不会被内置识别器再次命中


@dataclass(frozen=True)
class CoverageEvent:
    """一次覆盖命中的内部轨迹（仅位置/规则/动作/识别器，绝不含原值）。

    仅供策略变更对照等内存内分析使用（``collect_coverage=True`` 时收集），
    不落库、不写入任何文件。

    * ``span`` 为内容命中在**原始字符串**中的 ``(start, end)`` 偏移；
      整字段规则命中字符串时记为 ``(0, len(原值))``，命中非字符串标量时
      为 ``None``（表示整个值被处理，无字符坐标）。
    * 内嵌解码结构内的命中，``field_path`` 为组合路径（如
      ``$.payload.user.email``），``span`` 基于**解码后内层文本**的坐标；
      对照两侧以同一输入解码，坐标系一致、可稳定对齐。
    """

    record_index: int
    line_no: int | None
    field_path: str
    key_name: str | None
    span: tuple[int, int] | None
    rule_id: str
    rule_name: str
    action: str
    match_type: str
    hit_by: tuple[str, ...]


@dataclass(frozen=True)
class _DecodeCtx:
    """当前所处的内嵌解码层级上下文。

    * ``depth`` 为 0 表示不在任何解码结构内（记录顶层字段）；
    * ``root`` 为本层级解码根的内部路径（如 ``payload``、``payload.inner``），
      用于推导审计/风险条目中的外层字段路径与内部相对路径。
    """

    depth: int = 0
    root: str = ""


_ROOT_CTX = _DecodeCtx()


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


# ---------- 字段/键名维度匹配（规则与解码器声明共用） ----------


def _field_key_matches(
    field_paths: list[str],
    path_res: list[re.Pattern[str]],
    key_names: set[str],
    key_globs: list[str],
    key_glob_res: list[re.Pattern[str]],
    key_patterns: list[str],
    key_pat_res: list[re.Pattern[str]],
    path: str,
    key: str | None,
) -> bool:
    """字段路径与键名维度的 AND/OR 语义（与策略规则一致）。"""
    # 路径维度：任一 field_path 命中即可
    if field_paths and not any(rx.fullmatch(path) for rx in path_res):
        return False
    # 键名维度：key_names / key_globs / key_patterns 三者之间是 OR
    if any([key_names, key_globs, key_patterns]):
        key_hit = (
            (bool(key_names) and key in key_names)
            or (
                bool(key_globs)
                and key is not None
                and any(rx.fullmatch(key) for rx in key_glob_res)
            )
            or (
                bool(key_patterns)
                and key is not None
                and any(rx.search(key) for rx in key_pat_res)
            )
        )
        if not key_hit:
            return False
    return True


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
        return _field_key_matches(
            m.field_paths, self.path_res, self.key_names,
            m.key_globs, self.key_glob_res, m.key_patterns, self.key_pat_res,
            path, key,
        )


@dataclass
class CompiledDecoder:
    """编译后的内嵌解码器声明（与规则同一套字段/键名匹配语义）。"""

    spec: EmbeddedDecoder
    path_res: list[re.Pattern[str]] = field(default_factory=list)
    key_names: set[str] = field(default_factory=set)
    key_glob_res: list[re.Pattern[str]] = field(default_factory=list)
    key_pat_res: list[re.Pattern[str]] = field(default_factory=list)

    def matches(self, path: str, key: str | None) -> bool:
        s = self.spec
        return _field_key_matches(
            s.field_paths, self.path_res, self.key_names,
            s.key_globs, self.key_glob_res, s.key_patterns, self.key_pat_res,
            path, key,
        )


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


def compile_decoders(decoders: list[EmbeddedDecoder]) -> list[CompiledDecoder]:
    return [
        CompiledDecoder(
            spec=d,
            path_res=[glob_to_regex(p) for p in d.field_paths],
            key_names=set(d.key_names),
            key_glob_res=[glob_to_regex(g) for g in d.key_globs],
            key_pat_res=[re.compile(p) for p in d.key_patterns],
        )
        for d in decoders
    ]


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


# ---------- 引擎 ----------


class RedactionEngine:
    def __init__(self, strategy: Strategy, key: MasterKey, is_ndjson: bool = False,
                 collect_coverage: bool = False,
                 domain_fingerprint: str = "global") -> None:
        self.strategy = strategy
        self.compiled = compile_strategy(strategy)
        self.field_rules = [c for c in self.compiled if c.is_field_rule]
        self.content_rules = [c for c in self.compiled if c.is_content_rule]
        # 内嵌结构解码器：按声明顺序首个命中的解码器生效
        self.decoders = compile_decoders(strategy.decoders)
        self.max_decode_depth = strategy.max_decode_depth
        self.max_decode_bytes = strategy.max_decode_bytes
        # key 为生效密钥：全局域即主密钥，隔离域为主密钥派生的域子密钥
        # （由 crypto.resolve_token_domain 解析），引擎本身不感知上下文原文。
        self.key = key
        # 仅用于结果展示：令牌实际所在的关联域指纹（global / dom:<hex>）
        self.domain_fingerprint = domain_fingerprint
        self.is_ndjson = is_ndjson
        self.audit: list[AuditEntry] = []
        self.risks: list[RiskFinding] = []
        # 内嵌解码未执行（保持原值）的待复核原因
        self.decode_issues: list[DecodeIssue] = []
        # 覆盖轨迹（策略变更对照用）：仅 collect_coverage=True 时收集，纯内存
        self.collect_coverage = collect_coverage
        self.coverage: list[CoverageEvent] = []
        self.fields_scanned = 0
        self.by_rule: dict[str, int] = {}
        self.by_action: dict[str, int] = {}
        # 整批共享的替身表：键为原始值（含类型前缀），与命中规则无关，
        # 因此同一值即使被不同规则命中也恒为同一替身。
        self._text_tokens: dict[str, str] = {}
        self._int_tokens: dict[str, int] = {}
        self._float_tokens: dict[str, float] = {}
        # (record_index, field_path)：被整字段规则处理过的叶子，
        # 残留风险扫描时整体跳过（掩码前缀可能形似原数据，如 z***@example.com）
        self._fully_handled: set[tuple[int, str]] = set()
        # (record_index, field_path)：已完成内嵌解码处理的字段；其内部结构的
        # 残留风险已在解码时按内层路径扫描，外层字符串不再重复扫描
        self._decoded_fields: set[tuple[int, str]] = set()
        # 当前记录对应的 NDJSON 行号；逐记录流式处理时由外部显式指定，
        # 批量 run() 按记录序号推导（与历史行为一致）
        self.current_line_no: int | None = None
        # 已在检查点落库、已从 self.risks 排空的风险数；用于跨检查点维持上限
        self.risk_base = 0
        # 与 risk_base 同理：已排空的内嵌解码待复核条数
        self.issue_base = 0

    def _token_str(self, raw: str) -> str:
        token = self._text_tokens.get(raw)
        if token is None:
            token = deterministic_token(self.key, raw)
            self._text_tokens[raw] = token
        return token

    def _token_number(self, value: int | float) -> int | float:
        if isinstance(value, int):
            token = self._int_tokens.get(str(value))
            if token is None:
                token = deterministic_number_token(self.key, value)  # type: ignore[arg-type]
                self._int_tokens[str(value)] = token
            return token
        token = self._float_tokens.get(str(value))
        if token is None:
            token = deterministic_number_token(self.key, value)  # type: ignore[assignment]
            self._float_tokens[str(value)] = token
        return token

    def _event_line_no(self, idx: int) -> int | None:
        if not self.is_ndjson:
            return None
        return self.current_line_no if self.current_line_no is not None else idx + 1

    @staticmethod
    def _decode_locations(path: str, ctx: _DecodeCtx
                          ) -> tuple[str | None, str | None]:
        """由解码上下文推导 (外层字段路径, 内部相对路径)；未在解码结构内为 (None, None)。"""
        if ctx.depth == 0:
            return None, None
        rel = path[len(ctx.root):] if path.startswith(ctx.root) else path
        if rel.startswith("."):
            rel = rel[1:]
        return display_path(ctx.root), display_path(rel)

    def _record_audit(self, idx: int, path: str, key: str | None, cr: CompiledRule,
                      match_type: str, hit_by: list[str], occurrences: int = 1,
                      ctx: _DecodeCtx = _ROOT_CTX) -> None:
        outer, inner = self._decode_locations(path, ctx)
        self.audit.append(
            AuditEntry(
                record_index=idx,
                line_no=self._event_line_no(idx),
                field_path=display_path(path),
                key_name=key,
                rule_id=cr.rule.id,
                rule_name=cr.rule.name,
                action=cr.rule.action,
                match_type=match_type,  # type: ignore[arg-type]
                hit_by=hit_by,
                occurrences=occurrences,
                decode_depth=ctx.depth,
                outer_field_path=outer,
                inner_path=inner,
            )
        )
        self.by_rule[cr.rule.id] = self.by_rule.get(cr.rule.id, 0) + 1
        self.by_action[cr.rule.action] = self.by_action.get(cr.rule.action, 0) + 1

    def _record_coverage(self, idx: int, path: str, key: str | None, cr: CompiledRule,
                         match_type: str, hit_by: tuple[str, ...],
                         span: tuple[int, int] | None) -> None:
        if not self.collect_coverage:
            return
        self.coverage.append(
            CoverageEvent(
                record_index=idx,
                line_no=self._event_line_no(idx),
                field_path=display_path(path),
                key_name=key,
                span=span,
                rule_id=cr.rule.id,
                rule_name=cr.rule.name,
                action=cr.rule.action,
                match_type=match_type,
                hit_by=hit_by,
            )
        )

    def _issue_cap_reached(self) -> bool:
        return self.issue_base + len(self.decode_issues) >= MAX_DECODE_ISSUES

    def _record_decode_issue(self, idx: int, path: str, decoder: str,
                             reason: str, ctx: _DecodeCtx, detail: str) -> None:
        if self._issue_cap_reached():
            return
        self.decode_issues.append(
            DecodeIssue(
                record_index=idx,
                line_no=self._event_line_no(idx),
                field_path=display_path(path),
                decoder=decoder,
                reason=reason,  # type: ignore[arg-type]
                decode_depth=ctx.depth + 1,
                detail=detail,
            )
        )

    # -- 单个标量叶子 --
    def _apply_leaf(self, value: Any, idx: int, path: str, key: str | None,
                    ctx: _DecodeCtx = _ROOT_CTX) -> Any:
        self.fields_scanned += 1

        # 1) 整字段规则：按策略顺序第一个命中即生效
        for cr in self.field_rules:
            if cr.field_matches(path, key):
                self._record_audit(idx, path, key, cr, "field", ["field_match"], ctx=ctx)
                # 字符串整字段命中记为 (0, len)，便于与内容命中在同一坐标系对齐
                span = (0, len(value)) if isinstance(value, str) else None
                self._record_coverage(idx, path, key, cr, "field",
                                      ("field_match",), span)
                if path:
                    self._fully_handled.add((idx, path))
                return self._field_action(value, cr)

        # 2) 内嵌结构解码器：声明命中的字符串字段不再走内容规则，
        #    解码 → 内部递归应用完整规则集 → 编码回写；
        #    解码失败/层级/展开超限保持原值，只记录待复核原因
        if isinstance(value, str) and self.decoders:
            decoder = next((d for d in self.decoders if d.matches(path, key)), None)
            if decoder is not None:
                return self._apply_decoder(value, idx, path, key, ctx, decoder)

        # 3) 内容规则：仅对字符串值做片段替换
        if isinstance(value, str):
            return self._apply_content_rules(value, idx, path, key, ctx)
        return value

    def _field_action(self, value: Any, cr: CompiledRule) -> Any:
        action = cr.rule.action
        if action == "delete":
            return None
        if action == "mask":
            return _mask_whole(value, cr.rule.mask_char, cr.rule.keep_prefix, cr.rule.keep_suffix)
        # tokenize：保留原值类型（str/int/float），bool/None 不处理
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return self._token_number(value)
        return self._token_str(str(value))

    # -- 内嵌结构解码 --

    def _apply_decoder(self, value: str, idx: int, path: str, key: str | None,
                       ctx: _DecodeCtx, decoder: CompiledDecoder) -> str:
        kind = decoder.spec.decoder
        # 嵌套层级超限：保持原值，只记录待复核原因
        if ctx.depth >= self.max_decode_depth:
            self._record_decode_issue(
                idx, path, kind, "depth_exceeded", ctx,
                f"内嵌解码层级超过策略上限（{self.max_decode_depth}）",
            )
            return value
        child_ctx = _DecodeCtx(depth=ctx.depth + 1, root=path)
        if kind == "json_string":
            return self._decode_json_string(value, idx, path, key, ctx, child_ctx)
        if kind == "url_query":
            return self._decode_url_query(value, idx, path, ctx, child_ctx)
        return self._decode_form_body(value, idx, path, ctx, child_ctx)

    def _decode_json_string(self, value: str, idx: int, path: str,
                            key: str | None, ctx: _DecodeCtx,
                            child_ctx: _DecodeCtx) -> str:
        try:
            data = decode_json_string(value)
        except DecodeError as exc:
            self._record_decode_issue(
                idx, path, "json_string", "decode_failed", ctx, str(exc))
            return value
        if not isinstance(data, (dict, list)):
            # 合法 JSON 标量：不作为内嵌结构展开，回退为普通内容规则处理
            return self._apply_content_rules(value, idx, path, key, ctx)
        expanded = json_expanded_bytes(data)
        if expanded > self.max_decode_bytes:
            self._record_decode_issue(
                idx, path, "json_string", "bytes_exceeded", ctx,
                f"展开后 {expanded} 字节超过上限（{self.max_decode_bytes}）",
            )
            return value
        processed = self._walk(data, idx, path, key, child_ctx)
        # 内层残留风险按内层路径扫描；外层字符串标记为已解码，不再重复扫描
        self._scan_risks(processed, idx, path, child_ctx)
        self._decoded_fields.add((idx, path))
        if processed == data:
            # 内部无改动：原样保留外层字符串（含原始转义与空白）
            return value
        return encode_json_string(processed)

    def _decode_url_query(self, value: str, idx: int, path: str,
                          ctx: _DecodeCtx, child_ctx: _DecodeCtx) -> str:
        try:
            parts = split_url_query(value)
        except DecodeError as exc:
            self._record_decode_issue(
                idx, path, "url_query", "decode_failed", ctx, str(exc))
            return value
        new_query = self._process_query(
            parts.query, idx, path, ctx, child_ctx, "url_query")
        if new_query is None:
            return value  # 展开超限，已记录待复核
        self._decoded_fields.add((idx, path))
        if new_query == parts.query:
            return value  # 无改动：非查询部分、编码与顺序逐字节保留
        return parts.prefix + "?" + new_query + parts.fragment

    def _decode_form_body(self, value: str, idx: int, path: str,
                          ctx: _DecodeCtx, child_ctx: _DecodeCtx) -> str:
        new_body = self._process_query(
            value, idx, path, ctx, child_ctx, "form_urlencoded")
        if new_body is None:
            return value  # 展开超限，已记录待复核
        self._decoded_fields.add((idx, path))
        return new_body

    def _process_query(self, query: str, idx: int, path: str,
                       ctx: _DecodeCtx, child_ctx: _DecodeCtx,
                       kind: str) -> str | None:
        """逐段处理查询串/表单体，返回新串；展开超限返回 None（已记录待复核）。

        参数顺序、重复键、空值与旗标参数全部保留；未被规则改写的段原样
        回写（原始百分号编码逐字节保留），只有被改写的段重新编码。
        """
        segments = parse_query_segments(query)
        expanded = query_expanded_bytes(segments)
        if expanded > self.max_decode_bytes:
            self._record_decode_issue(
                idx, path, kind, "bytes_exceeded", ctx,
                f"展开后 {expanded} 字节超过上限（{self.max_decode_bytes}）",
            )
            return None
        out: list[str] = []
        for seg in segments:
            param_path = f"{path}.{seg.key}" if path else seg.key
            new_value = self._apply_leaf(seg.value, idx, param_path, seg.key,
                                         child_ctx)
            if new_value is None:
                # delete：置空、保留键与位置
                out.append(seg.raw_key + "=")
                # 删除后无残留内容可扫
            elif new_value == seg.value:
                out.append(seg.raw)  # 未改写：原始编码逐字节保留
                self._scan_risks(seg.value, idx, param_path, child_ctx)
            else:
                out.append(seg.raw_key + "=" + encode_query_value(new_value))
                self._scan_risks(new_value, idx, param_path, child_ctx)
        return "&".join(out)

    def _apply_content_rules(self, text: str, idx: int, path: str, key: str | None,
                             ctx: _DecodeCtx = _ROOT_CTX) -> str:
        # 候选片段按规则定义顺序贪心占位，重叠片段归先定义的规则
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

        # edits: (start, end, replacement)，同一规则的命中信息另外审计
        edits: list[tuple[int, int, str]] = []
        for cr in self.content_rules:
            if cr.rule.match.has_field_dimension() and not cr.field_matches(path, key):
                continue
            candidates: list[tuple[int, int]] = []
            labels: list[str] = []
            for pat_i, pat in enumerate(cr.value_pat_res):
                spans = [(m.start(), m.end()) for m in pat.finditer(text)]
                if spans:
                    candidates.extend(spans)
                    # 只记录序号，绝不把原始正则文本写入审计
                    labels.append(f"value_pattern#{pat_i + 1}")
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
            self._record_audit(
                idx, path, key, cr, "content", labels, occurrences=len(spans),
                ctx=ctx,
            )
            for s, e in spans:
                self._record_coverage(idx, path, key, cr, "content",
                                      tuple(labels), (s, e))
            # 替换串在任何改写之前基于原文计算，避免读到已被改写的文本
            for s, e in spans:
                original = text[s:e]
                if cr.rule.action == "delete":
                    replacement = ""
                elif cr.rule.action == "mask":
                    middle_len = max(1, len(original) - cr.rule.keep_prefix - cr.rule.keep_suffix)
                    replacement = (
                        original[: cr.rule.keep_prefix]
                        + cr.rule.mask_char * middle_len
                        + (original[len(original) - cr.rule.keep_suffix:]
                           if cr.rule.keep_suffix else "")
                    )
                else:
                    replacement = self._token_str(original)
                edits.append((s, e, replacement))

        if not edits:
            return text

        # 全部命中按起点统一降序替换：只依赖自身起点之前的文本长度，
        # 不会因为别的替换改变长度而发生位置偏移、留下或截断已命中原文
        out = text
        for s, e, replacement in sorted(edits, key=lambda x: (x[0], x[1]), reverse=True):
            out = out[:s] + replacement + out[e:]
        return out

    # -- 递归遍历 --
    def _walk(self, node: Any, idx: int, path: str, key: str | None,
              ctx: _DecodeCtx = _ROOT_CTX) -> Any:
        if isinstance(node, dict):
            return {
                k: self._walk(v, idx, f"{path}.{k}" if path else k, k, ctx)
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [
                self._walk(v, idx, f"{path}[{i}]", key, ctx)
                for i, v in enumerate(node)
            ]
        return self._apply_leaf(node, idx, path, key, ctx)

    # -- 残留风险扫描 --
    def _risk_cap_reached(self) -> bool:
        return self.risk_base + len(self.risks) >= MAX_RISK_FINDINGS

    def _scan_risks(self, node: Any, idx: int, path: str,
                    ctx: _DecodeCtx = _ROOT_CTX) -> None:
        if self._risk_cap_reached():
            return
        if isinstance(node, dict):
            for k, v in node.items():
                self._scan_risks(v, idx, f"{path}.{k}" if path else k, ctx)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                self._scan_risks(v, idx, f"{path}[{i}]", ctx)
        elif path and (idx, path) in self._fully_handled:
            return
        elif path and (idx, path) in self._decoded_fields:
            # 内嵌结构的残留风险已在解码时按内层路径扫描，不重复计
            return
        elif isinstance(node, str):
            found = scan(node, self.strategy.risk_detectors)
            outer, inner = self._decode_locations(path, ctx)
            for det_name, spans in found.items():
                for s, e in spans:
                    # 跳过本工具生成的确定性令牌，避免把替身误判为残留敏感内容
                    if node[s:e].startswith(_TOKEN_PREFIX):
                        continue
                    self.risks.append(
                        RiskFinding(
                            record_index=idx,
                            line_no=self._event_line_no(idx),
                            field_path=display_path(path),
                            detector=det_name,
                            length=e - s,
                            decode_depth=ctx.depth,
                            outer_field_path=outer,
                            inner_path=inner,
                        )
                    )
                    if self._risk_cap_reached():
                        return

    # -- 逐记录流式处理 --

    def process_record(self, record: Any, idx: int,
                       line_no: int | None = None) -> Any:
        """处理单条记录并做残留风险扫描（流式作业逐条调用）。

        审计、风险与解码待复核事件累积在引擎内，由 :meth:`drain_events`
        在安全检查点排空。
        """
        self.current_line_no = line_no
        if isinstance(record, (dict, list)):
            out = self._walk(record, idx, "", None)
        else:
            # 顶层标量日志：作为根叶子处理（规则可用 field_path "$"）
            self.fields_scanned += 1
            out = self._apply_leaf(record, idx, "", None)
        self._scan_risks(out, idx, "")
        return out

    def process_text_line(self, text: str, idx: int,
                          line_no: int | None = None) -> str:
        """处理一行非结构化文本（.log/.txt）：仅内容规则生效。

        整字段规则依赖 JSON 结构（字段路径/键名），对纯文本行没有意义；
        内容规则（value_patterns/detectors）按行内片段替换。审计/风险的
        field_path 恒为 ``$``，位置由 line_no（行号）与 record_index 表达。
        """
        self.current_line_no = line_no
        self.fields_scanned += 1
        out = self._apply_content_rules(text, idx, "", None)
        self._scan_risks(out, idx, "")
        return out

    def drain_events(self) -> tuple[list[AuditEntry], list[RiskFinding],
                                    list[DecodeIssue]]:
        """取出并清空自上次排空以来累积的审计、风险与解码待复核事件（检查点调用）。"""
        audit, self.audit = self.audit, []
        risks, self.risks = self.risks, []
        issues, self.decode_issues = self.decode_issues, []
        self.risk_base += len(risks)
        self.issue_base += len(issues)
        return audit, risks, issues

    def run(self, records: list[Any]) -> RunResult:
        out: list[Any] = []
        self.current_line_no = None
        for idx, record in enumerate(records):
            out.append(self.process_record(record, idx))

        stats = RunStats(
            records_in=len(records),
            fields_scanned=self.fields_scanned,
            audit_entries=len(self.audit),
            risk_findings=len(self.risks),
            decode_issues=len(self.decode_issues),
            by_action=self.by_action,
            by_rule=self.by_rule,
        )
        return RunResult(
            records=out,
            audit=self.audit,
            risks=self.risks,
            decode_issues=self.decode_issues,
            stats=stats,
            needs_review=bool(self.risks or self.decode_issues),
            key_fingerprint=key_fingerprint(self.key),
            domain_fingerprint=self.domain_fingerprint,
        )


def run_strategy(strategy: Strategy, records: list[Any], key: MasterKey,
                 is_ndjson: bool = False,
                 domain_fingerprint: str = "global") -> RunResult:
    return RedactionEngine(
        strategy, key, is_ndjson=is_ndjson,
        domain_fingerprint=domain_fingerprint,
    ).run(records)
