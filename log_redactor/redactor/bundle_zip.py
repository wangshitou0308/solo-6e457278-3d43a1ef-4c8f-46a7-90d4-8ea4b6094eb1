"""诊断包（ZIP）安全校验：拒绝不安全的压缩包并给出全部原因。

校验在**上传落盘后、创建作业前**执行，不安全的压缩包整体拒绝（HTTP 422）：

* 路径穿越：绝对路径、``..`` 组件、Windows 盘符、反斜杠分隔符、NUL 字符；
* 符号链接与特殊文件（按 unix 模式位判断）；
* 重复路径（规范化后同名）；
* 加密条目（general purpose flag 第 0 位）；
* 超限：文件数、单文件展开大小、展开总量、压缩比（防 zip 炸弹）。

只读中央目录做判定，**不解压任何内容**；真正的解压在 worker 内流式进行，
并再次按实际上限计数防御伪造的尺寸头。
"""
from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass

# 结果 ZIP 内清单的保留文件名（位于根目录）
MANIFEST_NAME = "redaction-manifest.json"

# 单文件超过该大小才做压缩比检查：小文件天然比值偏高，避免误伤
_RATIO_CHECK_FLOOR = 1024 * 1024
# 一次校验最多报告的拒绝原因条数（防止畸形包制造超大响应）
_MAX_REASONS = 20

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(lo, min(value, hi))


def max_files() -> int:
    """压缩包内允许的最大文件条目数。"""
    return _env_int("REDACTOR_BUNDLE_MAX_FILES", 2000, 1, 1_000_000)


def max_file_bytes() -> int:
    """单个文件展开后的最大字节数。"""
    return _env_int("REDACTOR_BUNDLE_MAX_FILE_BYTES", 64 * 1024 * 1024, 1024, 1 << 40)


def max_total_bytes() -> int:
    """全部文件展开总量的最大字节数（同时作为上传压缩态上限）。"""
    return _env_int("REDACTOR_BUNDLE_MAX_TOTAL_BYTES", 512 * 1024 * 1024, 1024, 1 << 40)


def max_ratio() -> float:
    """允许的最大压缩比（展开/压缩），防 zip 炸弹。"""
    raw = os.environ.get("REDACTOR_BUNDLE_MAX_RATIO")
    try:
        value = float(raw) if raw not in (None, "") else 100.0
    except ValueError:
        value = 100.0
    return max(1.0, min(value, 1_000_000.0))


class BundleRejection(ValueError):
    """压缩包未通过安全校验；reasons 为人类可读的全部原因（截断到上限）。"""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("；".join(reasons))
        self.reasons = reasons


@dataclass
class BundleEntry:
    """通过校验、等待处理的一个文件条目。"""

    name: str  # 规范化后的相对路径（结果 ZIP 中沿用）
    info: zipfile.ZipInfo


def normalize_entry_name(name: str) -> str | None:
    """把条目名规范化为安全的相对路径；不合法时返回 ``None``。

    合法化规则：去掉 ``.`` 组件与空组件；拒绝绝对路径、盘符、反斜杠、
    NUL、``..`` 组件。调用方对返回 ``None`` 的条目记录拒绝原因。
    """
    if not name or "\x00" in name:
        return None
    if "\\" in name:
        # 反斜杠在 Windows 上是分隔符，存在穿越歧义，一律拒绝
        return None
    if name.startswith("/") or _DRIVE_RE.match(name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    normalized = "/".join(parts)
    return normalized or None


def _is_symlink_or_special(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    # 仅看文件类型位：writestr 等工具只写权限位（如 0o600，无 S_IFREG），
    # 这种"只有权限、没有类型"的条目是普通文件，不能误判为特殊文件
    file_type = stat.S_IFMT(mode)
    if file_type == 0:
        return False
    if stat.S_ISLNK(mode):
        return True
    # 有类型位但不是普通文件/目录（socket/fifo/设备）同样拒绝
    return not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))


def validate_bundle(path: "os.PathLike[str] | str") -> list[BundleEntry]:
    """校验压缩包并返回可处理文件条目（目录条目被忽略）。

    任何一类问题都整体拒绝，抛出 :class:`BundleRejection`（含全部原因）。
    """
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise BundleRejection([f"不是合法的 ZIP 压缩包：{exc}"]) from exc

    reasons: list[str] = []

    def reject(reason: str) -> None:
        if len(reasons) < _MAX_REASONS:
            reasons.append(reason)

    entries: list[BundleEntry] = []
    seen: set[str] = set()
    total_size = 0
    total_compressed = 0
    limit_files = max_files()
    limit_file = max_file_bytes()
    limit_total = max_total_bytes()
    limit_ratio = max_ratio()

    with zf:
        infos = zf.infolist()
    for info in infos:
        raw_name = info.filename
        # 加密条目：无法离线审计内容，拒绝
        if info.flag_bits & 0x1:
            reject(f"加密条目：{raw_name!r}")
            continue
        # 符号链接与特殊文件
        if _is_symlink_or_special(info):
            reject(f"符号链接或特殊文件：{raw_name!r}")
            continue
        # 路径安全（目录条目同样校验，防止穿越型目录名）
        normalized = normalize_entry_name(raw_name)
        if normalized is None:
            reject(f"非法或穿越路径：{raw_name!r}")
            continue
        if info.is_dir():
            continue  # 目录条目合法即忽略（结果 ZIP 只放文件）
        # 重复路径（规范化后）
        if normalized in seen:
            reject(f"重复路径：{normalized!r}")
            continue
        seen.add(normalized)
        # 单文件大小
        if info.file_size > limit_file:
            reject(f"单文件超过展开上限（{info.file_size} > {limit_file} 字节）：{normalized!r}")
            continue
        total_size += info.file_size
        total_compressed += info.compress_size
        # 单文件压缩比（仅对达到一定大小的文件检查）
        if (
            info.file_size > _RATIO_CHECK_FLOOR
            and info.compress_size > 0
            and info.file_size / info.compress_size > limit_ratio
        ):
            reject(
                f"压缩比超过上限（{info.file_size / info.compress_size:.0f}:1 > "
                f"{limit_ratio:.0f}:1）：{normalized!r}"
            )
            continue
        entries.append(BundleEntry(name=normalized, info=info))

    if len(entries) > limit_files:
        reject(f"文件数超过上限（{len(entries)} > {limit_files}）")
    if total_size > limit_total:
        reject(f"展开总量超过上限（{total_size} > {limit_total} 字节）")
    if (
        total_size > _RATIO_CHECK_FLOOR
        and total_compressed > 0
        and total_size / total_compressed > limit_ratio
    ):
        reject(
            f"整体压缩比超过上限（{total_size / total_compressed:.0f}:1 > "
            f"{limit_ratio:.0f}:1）"
        )
    if not entries and not reasons:
        reject("压缩包为空（没有任何文件条目）")

    if reasons:
        raise BundleRejection(reasons)
    return entries
