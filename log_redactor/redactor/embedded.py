"""内嵌结构解码器：json_string / url_query / form_urlencoded 的纯解析与回写。

本模块只做字符串 ↔ 结构的转换，不感知规则与引擎：

* ``json_string``：``json.loads`` / ``json.dumps``（ensure_ascii=False）；
  仅对象/数组视为可展开的内嵌结构（标量由调用方回退为普通内容规则处理）。
* ``url_query``：把 URL 拆成 非查询部分 / 查询串 / 片段；查询串按 ``&`` 切段，
  保留参数顺序、重复查询键、空值、无 ``=`` 的旗标参数，以及**未修改段的
  原始百分号编码**（只有被规则改写的段才重新编码）。
* ``form_urlencoded``：整串即表单体，与查询串同一套段处理。

解码后的键/值按 ``unquote_plus`` 还原（``+`` 视为空格，与表单编码一致）；
被改写值的回写编码为 ``quote_plus``（``*`` 保持字面，掩码结果可读）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, unquote_plus


class DecodeError(ValueError):
    """内嵌结构解码失败（异常信息不含原始值）。"""


# ---------- json_string ----------


def decode_json_string(value: str) -> Any:
    """解析 JSON 文本；失败抛 :class:`DecodeError`。

    调用方需自行判断结果是否为对象/数组（标量不作为内嵌结构展开）。
    """
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise DecodeError(
            f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
        ) from exc
    except RecursionError as exc:
        raise DecodeError("JSON 嵌套过深，解析被拒绝") from exc


def encode_json_string(data: Any) -> str:
    """把处理后的结构重新序列化为合法 JSON 文本（与服务输出同一风格）。"""
    return json.dumps(data, ensure_ascii=False)


def json_expanded_bytes(data: Any) -> int:
    """JSON 结构规范化展开后的 UTF-8 字节数（展开字节上限的度量）。"""
    return len(encode_json_string(data).encode("utf-8"))


# ---------- url_query / form_urlencoded ----------


@dataclass(frozen=True)
class UrlParts:
    """URL 的三段拆分：查询串之外的部分全部原样保留。"""

    prefix: str  # "?" 之前的非查询部分（scheme/host/path 等，原样保留）
    query: str  # 查询串原文（不含 "?" 与片段）
    fragment: str  # "#" 起的片段（含 "#"，原样保留）


def split_url_query(value: str) -> UrlParts:
    """拆分 URL；不含 ``?`` 时抛 :class:`DecodeError`（无查询串可解析）。"""
    q = value.find("?")
    if q == -1:
        raise DecodeError("URL 中不含查询串")
    rest = value[q + 1:]
    hash_idx = rest.find("#")
    if hash_idx == -1:
        return UrlParts(prefix=value[:q], query=rest, fragment="")
    return UrlParts(prefix=value[:q], query=rest[:hash_idx],
                    fragment=rest[hash_idx:])


@dataclass(frozen=True)
class QuerySegment:
    """查询串/表单体中的一个参数段（``key``、``key=``、``key=value`` 三种形态）。"""

    raw: str  # 整段原文（未修改时原样回写，保留原始百分号编码）
    raw_key: str  # 原始（仍百分号编码）键
    raw_value: str | None  # 原始值；None 表示无 "=" 的旗标参数
    key: str  # 百分号解码后的键（用于字段路径与键名匹配）
    value: str  # 百分号解码后的值（旗标参数为 ""）


def parse_query_segments(query: str) -> list[QuerySegment]:
    """把查询串/表单体按 ``&`` 切成参数段，保留顺序、重复键与空值。"""
    if query == "":
        return []
    segments: list[QuerySegment] = []
    for part in query.split("&"):
        if "=" in part:
            raw_key, raw_value = part.split("=", 1)
        else:
            raw_key, raw_value = part, None
        segments.append(
            QuerySegment(
                raw=part,
                raw_key=raw_key,
                raw_value=raw_value,
                key=unquote_plus(raw_key),
                value=unquote_plus(raw_value) if raw_value is not None else "",
            )
        )
    return segments


def query_expanded_bytes(segments: list[QuerySegment]) -> int:
    """参数键值解码后的 UTF-8 字节总量（展开字节上限的度量）。"""
    return sum(
        len(s.key.encode("utf-8")) + len(s.value.encode("utf-8"))
        for s in segments
    )


def encode_query_value(value: str) -> str:
    """回写被规则改写的参数值：表单风格百分号编码（空格为 ``+``）。

    ``*`` 是 RFC 3986 sub-delim，在查询串/表单体中合法，保持字面可让
    掩码结果（如 ``a***``）直接可读；令牌（``T-…``，base32）无需编码。
    """
    return quote_plus(value, safe="*")


def render_segment(raw_key: str, new_value: str | None) -> str:
    """渲染被改写的参数段；``new_value=None`` 表示 delete（置空、保留键）。"""
    if new_value is None:
        return raw_key + "="
    return raw_key + "=" + encode_query_value(new_value)
