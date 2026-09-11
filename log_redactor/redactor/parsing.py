"""日志批次解析：JSON（对象或数组）与 NDJSON（每行一个 JSON 对象）。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class PayloadError(ValueError):
    def __init__(self, message: str, *, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


@dataclass(frozen=True)
class ParsedBatch:
    records: list[Any]
    # 提交的 JSON 顶层是否为数组；下载时需原样保留（单元素数组也不能解包成对象）
    top_level_is_array: bool


def parse_batch_indexed(content: str, fmt: str) -> tuple[ParsedBatch, list[int | None]]:
    """解析批次并返回每条记录的物理行号（JSON 格式恒为 None）。

    NDJSON 空行占行号但不占记录序号：``line_nos[i]`` 是 ``records[i]``
    在原文中的物理行号（从 1 开始），供需要稳定行号对齐的调用方使用。
    """
    if fmt == "json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PayloadError(
                f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
            ) from exc
        if isinstance(data, list):
            records = data
            is_array = True
        else:
            records = [data]
            is_array = False
        if not records:
            raise PayloadError("日志批次为空")
        return ParsedBatch(records=records, top_level_is_array=is_array), \
            [None] * len(records)

    if fmt == "ndjson":
        records: list[Any] = []
        line_nos: list[int] = []
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
                line_nos.append(lineno)
            except json.JSONDecodeError as exc:
                raise PayloadError(
                    f"NDJSON 第 {lineno} 行解析失败：{exc.msg}", line=lineno
                ) from exc
        if not records:
            raise PayloadError("日志批次为空（没有任何非空行）")
        return ParsedBatch(records=records, top_level_is_array=True), line_nos

    raise PayloadError(f"不支持的格式：{fmt}")


def parse_batch(content: str, fmt: str) -> ParsedBatch:
    return parse_batch_indexed(content, fmt)[0]
