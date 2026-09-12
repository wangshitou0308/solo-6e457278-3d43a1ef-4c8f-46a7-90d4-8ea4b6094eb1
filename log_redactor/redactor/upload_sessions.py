"""断点续传上传会话：声明式创建、Content-Range 乱序分片、完成后转入既有作业。

设计要点
--------
* 创建会话时声明文件类型（ndjson/zip）、总字节数、整体 SHA-256、脱敏策略与
  令牌关联域上下文；服务只持久化**不可逆域标识**，不保存上下文原文。
* 分片经 ``Content-Range: bytes <start>-<end>/<total>`` 乱序提交，逐块流式
  写入 ``uploads/{session_id}.part``（**0600** 权限），不以整包进内存；
  每片落盘并 fsync 后才在 ``upload_chunks`` 索引登记 (start, end, sha256)，
  因此**已登记的分片必然已在盘上**，服务重启后凭索引直接恢复进度。
* 同一区间内容一致（逐片 SHA-256 相同）的重传是**幂等回放**；区间重叠冲突、
  越界或摘要不符一律拒绝，**已登记分片原样保留**。
* 完成时要求分片恰好覆盖 ``[0, bytes_total)`` 且整体 SHA-256 与声明一致；
  NDJSON 直接转入既有流式作业，ZIP 先过原有安全校验再转入诊断包作业，
  策略、令牌关联域与 Idempotency-Key 全部沿用会话创建时的声明。
* 会话有有效期（默认 24 小时）；过期/终止/失败时清理暂存文件与分片索引，
  完成后禁止继续写入。
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import threading
from pathlib import Path
from typing import Any, Callable

from . import config
from .crypto import domain_fingerprint
from .database import Database, utcnow_iso
from .stream_jobs import tighten

# 分片暂存目录：$REDACTOR_DATA_DIR/uploads/
_TMP_PREFIX = ".tmp-"

# Content-Range: bytes <start>-<end>/<total>（end 为闭区间，内部统一转开区间）
_CONTENT_RANGE_RE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")

# 流式落盘的拷贝块大小（与 app.UPLOAD_CHUNK 一致）
COPY_CHUNK = 1024 * 1024


def uploads_dir() -> Path:
    return config.settings.data_dir / "uploads"


def staged_path(session_id: str) -> Path:
    return uploads_dir() / f"{session_id}.part"


def ensure_upload_dirs() -> None:
    uploads_dir().mkdir(parents=True, exist_ok=True)


def session_ttl_seconds() -> int:
    """会话默认有效期（秒）：``REDACTOR_UPLOAD_SESSION_TTL_SECONDS``，默认 24h。"""
    raw = os.environ.get("REDACTOR_UPLOAD_SESSION_TTL_SECONDS", "86400")
    try:
        value = int(raw)
    except ValueError:
        value = 86400
    return max(60, min(value, 7 * 24 * 3600))


def tighten(path: Path) -> None:
    """把暂存文件权限收紧为仅属主可读写（0600）。"""
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current != 0o600:
            os.chmod(path, 0o600)
    except FileNotFoundError:
        pass


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def create_staged_file(session_id: str) -> Path:
    """以 0600 权限创建空的暂存文件（O_EXCL 防并发覆盖）。"""
    ensure_upload_dirs()
    path = staged_path(session_id)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)
    _fsync_dir(path.parent)
    return path


def ensure_staged_file(session_id: str) -> Path:
    """确保暂存文件存在（分片写入路径）：缺失时以 0600 重建，存在时收紧权限。

    恢复对账可能因暂存文件丢失而重置分片索引；客户端重传时按调用本函数
    惰性重建，无需重新创建会话。
    """
    ensure_upload_dirs()
    path = staged_path(session_id)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    tighten(path)
    return path


def cleanup_session_files(session_id: str) -> None:
    """删除会话的暂存文件与完成/终止时的孤儿临时文件（幂等）。"""
    staged_path(session_id).unlink(missing_ok=True)
    for orphan in uploads_dir().glob(f"{_TMP_PREFIX}{session_id}-*"):
        orphan.unlink(missing_ok=True)


# ---------- Content-Range 解析 ----------


class ContentRangeError(ValueError):
    """Content-Range 头非法（格式/边界/与会话声明不一致）。"""

    def __init__(self, message: str, *, out_of_bounds: bool = False) -> None:
        super().__init__(message)
        self.out_of_bounds = out_of_bounds


def parse_content_range(header: str | None, bytes_total: int) -> tuple[int, int]:
    """解析 ``Content-Range: bytes <start>-<end>/<total>``，返回开区间 (start, end)。

    * 缺头/格式非法/空区间 → ``ContentRangeError(out_of_bounds=False)``；
    * 声明总长与会话不符、区间越出 ``[0, bytes_total)`` →
      ``ContentRangeError(out_of_bounds=True)``（调用方映射为 409）。
    """
    if not header:
        raise ContentRangeError("缺少 Content-Range 头（期望 bytes <start>-<end>/<total>）")
    m = _CONTENT_RANGE_RE.match(header.strip())
    if not m:
        raise ContentRangeError(
            f"Content-Range 格式非法：{header!r}（期望 bytes <start>-<end>/<total>）"
        )
    start, end_inclusive, total = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if total != bytes_total:
        raise ContentRangeError(
            f"Content-Range 总长 {total} 与会话声明的 {bytes_total} 字节不一致",
            out_of_bounds=True,
        )
    if end_inclusive < start:
        raise ContentRangeError("Content-Range 区间为空（end 小于 start）")
    end = end_inclusive + 1  # 闭区间 → 开区间
    if end > bytes_total:
        raise ContentRangeError(
            f"Content-Range 越界：区间终点 {end} 超出声明总长 {bytes_total}",
            out_of_bounds=True,
        )
    return start, end


# ---------- 区间合并与缺失计算 ----------


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """把（可能重叠/相邻的）开区间列表合并为不重叠的有序区间。"""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            last_start, last_end = merged[-1]
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def missing_ranges(bytes_total: int, merged: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """已合并区间的补集：``[0, bytes_total)`` 内仍缺失的区间。"""
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in merged:
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < bytes_total:
        gaps.append((cursor, bytes_total))
    return gaps


def ranges_fully_cover(merged: list[tuple[int, int]], bytes_total: int) -> bool:
    return merged == [(0, bytes_total)]


# ---------- 会话内分片写入串行化（进程内） ----------

_locks_guard = threading.Lock()
_session_locks: dict[str, threading.Lock] = {}


def session_lock(session_id: str) -> threading.Lock:
    """每个会话一把锁：分片写入/完成/终止互斥，避免索引与暂存文件竞争。"""
    with _locks_guard:
        lock = _session_locks.get(session_id)
        if lock is None:
            lock = threading.Lock()
            _session_locks[session_id] = lock
        return lock


def reset_session_locks() -> None:
    """测试辅助：清空会话锁表。"""
    with _locks_guard:
        _session_locks.clear()


# ---------- 会话视图模型 ----------


def session_to_model(row, db: Database) -> dict[str, Any]:
    """把 upload_sessions 行 + 分片索引组装成 API 视图（不含任何文件内容）。"""
    import json as _json

    from .models import ByteRange

    session_id = row["id"]
    bytes_total = int(row["bytes_total"])
    chunks = db.upload_chunks(session_id) if row["status"] == "uploading" else []
    merged = merge_ranges([(int(c["start"]), int(c["end"])) for c in chunks])
    received = sum(end - start for start, end in merged)
    gaps = missing_ranges(bytes_total, merged)
    strategy = _json.loads(row["strategy_json"] or "{}")
    status = row["status"]
    job_id = row["job_id"]
    job_kind = "stream-jobs" if row["kind"] == "ndjson" else "bundle-jobs"
    pct = round(received * 100.0 / bytes_total, 2) if bytes_total else 0.0
    if status == "completed":
        pct = 100.0
    return {
        "id": session_id,
        "idempotency_key": row["idempotency_key"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "status": status,
        "kind": row["kind"],
        "source_filename": row["source_filename"],
        "bytes_total": bytes_total,
        "bytes_received": received,
        "content_sha256": row["content_sha256"],
        "strategy_name": strategy.get("name", ""),
        "strategy_version": str(strategy.get("version", "1")),
        "strategy_sha256": row["strategy_sha256"],
        "key_fingerprint": row["key_fingerprint"],
        "domain_fingerprint": domain_fingerprint(row["domain_id"]),
        "expires_at": row["expires_at"],
        "received_ranges": [
            ByteRange(start=s, end=e, bytes=e - s).model_dump() for s, e in merged
        ],
        "missing_ranges": [
            ByteRange(start=s, end=e, bytes=e - s).model_dump() for s, e in gaps
        ],
        "progress_pct": pct,
        "job_id": job_id,
        "job_url": (f"/api/v1/{job_kind}/{job_id}" if job_id else None),
        "error_message": row["error_message"],
    }


# ---------- 过期清理与重启恢复 ----------


def sweep_expired_sessions(db: Database) -> list[str]:
    """把到期的 uploading 会话置为 expired 并清理暂存文件与分片索引。"""
    expired_ids = db.expire_due_upload_sessions()
    for session_id in expired_ids:
        cleanup_session_files(session_id)
        db.delete_upload_chunks(session_id)
    return expired_ids


def abort_session(db: Database, session_id: str, *, status: str = "aborted",
                  error_message: str | None = None) -> None:
    """终止会话（abort/expired/failed 共用）：置终态、清暂存、清索引。"""
    db.update_upload_session_status(
        session_id, status, error_message=error_message
    )
    cleanup_session_files(session_id)
    db.delete_upload_chunks(session_id)


_recovery_lock = threading.Lock()
_recovery_done = False


def recover_upload_sessions(get_db: Callable[[], Database]) -> None:
    """服务启动后恢复上传会话：过期清理、孤儿文件清扫、索引与暂存文件对账。

    * 已过期的 uploading 会话置为 expired 并清理暂存；
    * 暂存文件丢失/小于已登记最大终点的会话，分片索引不可信：清空索引让
      客户端重传（已登记分片必然 fsync 过，正常重启不会走到这里）；
    * 没有会话记录的孤儿 ``.part``/临时文件直接删除。

    幂等：只执行一次；测试通过 :func:`reset_upload_recovery` 重置。
    """
    global _recovery_done
    with _recovery_lock:
        if _recovery_done:
            return
        _recovery_done = True

    ensure_upload_dirs()
    db = get_db()
    sweep_expired_sessions(db)
    known_ids: set[str] = set()
    for row in db.resumable_upload_sessions():
        session_id = row["id"]
        known_ids.add(session_id)
        _covered, max_end = db.upload_chunk_stats(session_id)
        staged = staged_path(session_id)
        if max_end == 0:
            continue  # 尚未收到分片
        staged_size = staged.stat().st_size if staged.is_file() else -1
        if staged_size < max_end:
            # 暂存文件缺失/被截断：索引与盘上内容不符，重置索引让客户端重传
            db.delete_upload_chunks(session_id)
    # 孤儿暂存/临时文件（无任何会话记录）：直接清理
    for path in uploads_dir().glob("*.part"):
        if path.stem not in known_ids:
            path.unlink(missing_ok=True)
    for path in uploads_dir().glob(f"{_TMP_PREFIX}*"):
        path.unlink(missing_ok=True)


def reset_upload_recovery() -> None:
    """测试辅助：允许再次触发恢复扫描。"""
    global _recovery_done
    with _recovery_lock:
        _recovery_done = False


def link_or_copy_staged(staged: Path, target: Path) -> None:
    """把暂存内容安置到目标路径：优先硬链接（同设备、零拷贝），跨设备回退复制。

    调用方在失败时负责删除 ``target``；源文件始终保留，由调用方决定何时删除。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(staged, target)
    except OSError:
        shutil.copyfile(staged, target)
    tighten(target)
