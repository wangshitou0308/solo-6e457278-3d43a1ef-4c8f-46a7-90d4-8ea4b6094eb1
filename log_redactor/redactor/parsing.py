"""日志批次解析：JSON（对象或数组）与 NDJSON（每行一个 JSON 对象）。"""
from __future__ import annotations

import json
from typing import Any


class PayloadError(ValueError):
    def __init__(self, message: str, *, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


def parse_batch(content: str, fmt: str) -> list[Any]:
    if fmt == "json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PayloadError(f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}") from exc
        if isinstance(data, list):
            records = data
        else:
            records = [data]
        if not records:
            raise PayloadError("日志批次为空")
        return records

    if fmt == "ndjson":
        records: list[Any] = []
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise PayloadError(
                    f"NDJSON 第 {lineno} 行解析失败：{exc.msg}", line=lineno
                ) from exc
        if not records:
            raise PayloadError("日志批次为空（没有任何非空行）")
        return records

    raise PayloadError(f"不支持的格式：{fmt}")
