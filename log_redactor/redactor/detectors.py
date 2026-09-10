"""内置疑似敏感信息识别器。

每个识别器对一段字符串扫描，返回若干 ``(start, end)`` 命中区间。
正则候选普遍配合代码校验（如 IPv4 分段、身份证校验码、银行卡 Luhn），
尽量压低误报。全部识别离线运行、无外部调用。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

Span = tuple[int, int]
Finder = Callable[[str], list[Span]]


@dataclass(frozen=True)
class Detector:
    name: str
    description: str
    find: Finder


# ---------- 单类型识别器 ----------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _find_email(text: str) -> list[Span]:
    return [(m.start(), m.end()) for m in _EMAIL_RE.finditer(text)]


_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


def _find_phone(text: str) -> list[Span]:
    return [(m.start(), m.end()) for m in _PHONE_RE.finditer(text)]


_IPV4_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def _find_ipv4(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _IPV4_CANDIDATE_RE.finditer(text):
        parts = m.group().split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            spans.append((m.start(), m.end()))
    return spans


_IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f:]{3,39}(?![0-9A-Fa-f:])")


def _find_ipv6(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _IPV6_CANDIDATE_RE.finditer(text):
        candidate = m.group()
        if candidate.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(candidate.strip(":"))
        except ValueError:
            continue
        spans.append((m.start(), m.end()))
    return spans


def _group_spans(pattern: re.Pattern[str], text: str, group: int = 1) -> list[Span]:
    """返回命名/编号捕获组的区间；未命中分组时退回整个匹配。"""
    spans: list[Span] = []
    for m in pattern.finditer(text):
        if m.group(group):
            spans.append((m.start(group), m.end(group)))
        else:
            spans.append((m.start(), m.end()))
    return spans


_BEARER_RE = re.compile(r"[Bb]earer\s+([A-Za-z0-9\-._~+/]+={0,2})")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
_CRED_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|authorization|password)"
    r"""\s*[:=]\s*["']?([A-Za-z0-9\-._~+/]{12,})"""
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")


def _find_access_token(text: str) -> list[Span]:
    spans: list[Span] = []
    spans.extend(_group_spans(_BEARER_RE, text))
    spans.extend((m.start(), m.end()) for m in _JWT_RE.finditer(text))
    spans.extend(_group_spans(_CRED_RE, text))
    spans.extend((m.start(), m.end()) for m in _LONG_TOKEN_RE.finditer(text))
    return _merge_spans(spans)


_ID_CARD_RE = re.compile(r"(?<!\d)(\d{17}[0-9Xx])(?!\d)")
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def _valid_id_card(num: str) -> bool:
    import datetime

    year, month, day = int(num[6:10]), int(num[10:12]), int(num[12:14])
    if not (1900 <= year <= datetime.date.today().year):
        return False
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    total = sum(int(num[i]) * _ID_WEIGHTS[i] for i in range(17))
    return _ID_CHECK[total % 11] == num[17].upper()


def _find_id_card(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _ID_CARD_RE.finditer(text):
        if _valid_id_card(m.group(1)):
            spans.append((m.start(1), m.end(1)))
    return spans


_DIGIT_RUN_RE = re.compile(r"(?<!\d)(\d{13,19})(?!\d)")


def _luhn_ok(num: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _find_bank_card(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _DIGIT_RUN_RE.finditer(text):
        num = m.group(1)
        # 18 位且符合身份证结构的留给 id_card 识别器
        if len(num) == 18 and _valid_id_card(num):
            continue
        if _luhn_ok(num):
            spans.append((m.start(1), m.end(1)))
    return spans


def _merge_spans(spans: list[Span]) -> list[Span]:
    """合并相交区间，避免同一片段被重复替换。"""
    if not spans:
        return []
    ordered = sorted(spans)
    merged: list[list[int]] = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


DETECTORS: dict[str, Detector] = {
    d.name: d
    for d in (
        Detector("email", "电子邮箱地址", _find_email),
        Detector("phone", "中国大陆手机号", _find_phone),
        Detector("ipv4", "IPv4 地址", _find_ipv4),
        Detector("ipv6", "IPv6 地址", _find_ipv6),
        Detector("access_token", "访问令牌/密钥（Bearer、JWT、key=xxx、长随机串）", _find_access_token),
        Detector("id_card", "中国大陆居民身份证号（带校验码验证）", _find_id_card),
        Detector("bank_card", "银行卡号（Luhn 校验）", _find_bank_card),
    )
}
DETECTOR_NAMES = frozenset(DETECTORS)


def scan(text: str, detector_names: list[str] | tuple[str, ...]) -> dict[str, list[Span]]:
    """按多个识别器扫描，返回 ``{识别器: [区间]}``（只含非空结果）。"""
    out: dict[str, list[Span]] = {}
    for name in dict.fromkeys(detector_names):  # 去重保序
        spans = DETECTORS[name].find(text)
        if spans:
            out[name] = spans
    return out
