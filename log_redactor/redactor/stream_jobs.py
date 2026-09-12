"""大批量 NDJSON 流式作业：逐行脱敏、安全检查点、取消与重启恢复。

设计要点
--------
* 上传的原始文件以 **0600** 权限落盘到 ``streams/raw/``；worker 以二进制
  逐行读取并跟踪字节偏移，**不把整包读入内存**。
* 每处理 ``REDACTOR_CHECKPOINT_RECORDS`` 条记录做一次安全检查点：
  先 flush+fsync 输出文件，再在同一 SQLite 事务提交进度与本批审计/风险。
  恢复时严格按已检查点的输出字节截断 partial 文件，保证检查点自洽。
* 取消意图同时保存在内存事件与数据库（``cancel_requested``），
  因此重启后恢复的作业也会停在检查点。
* 格式错误记录物理行号并立即终止作业（status=failed）。
* 完成后原子 rename 发布 ``streams/out/{id}.ndjson``；原始文件在
  完成/取消/失败后一律删除，取消/失败同时删除未完成输出。
"""
from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable

from . import config
from .crypto import (
    MasterKey,
    domain_fingerprint,
    resolve_token_domain,
)
from .database import Database
from .engine import RedactionEngine
from .models import AuditEntry, RiskFinding, Strategy
from .receipts import publish_stream_receipt, receipt_path_for_output


def checkpoint_records() -> int:
    raw = os.environ.get("REDACTOR_CHECKPOINT_RECORDS", "100")
    try:
        value = int(raw)
    except ValueError:
        value = 100
    return max(1, min(value, 10_000))


def streams_dir() -> Path:
    return config.settings.data_dir / "streams"


def raw_path(job_id: str) -> Path:
    return streams_dir() / "raw" / f"{job_id}.ndjson"


def partial_output_path(job_id: str) -> Path:
    return streams_dir() / "partial" / f"{job_id}.ndjson"


def final_output_path(job_id: str) -> Path:
    return streams_dir() / "out" / f"{job_id}.ndjson"


def ensure_stream_dirs() -> None:
    for d in (streams_dir() / "raw", streams_dir() / "partial", streams_dir() / "out"):
        d.mkdir(parents=True, exist_ok=True)


def tighten(path: Path) -> None:
    """把临时文件权限收紧为仅属主可读写（0600）。"""
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current != 0o600:
            os.chmod(path, 0o600)
    except FileNotFoundError:
        pass


def _fsync_dir(path: Path) -> None:
    """fsync 目录，保证 rename 发布本身落盘（失败时静默，属尽力而为）。"""
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_publish(src: Path, dst: Path) -> None:
    """同目录原子 rename 发布；目标继承 0600 权限并 fsync 目录。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    tighten(src)
    os.replace(src, dst)
    tighten(dst)
    _fsync_dir(dst.parent)


def cleanup_stream_files(job_id: str, *, keep_output: bool) -> None:
    """作业终结清理：原始文件必删；未发布成功时输出与凭证一并删除。"""
    raw_path(job_id).unlink(missing_ok=True)
    if not keep_output:
        partial_output_path(job_id).unlink(missing_ok=True)
        final_output_path(job_id).unlink(missing_ok=True)
        receipt_path_for_output(final_output_path(job_id)).unlink(missing_ok=True)


# ---------- 取消注册表（进程内） ----------


class JobRegistry:
    """跟踪本进程运行中的作业线程与取消事件。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._cancel: dict[str, threading.Event] = {}

    def start(self, job_id: str, target: Callable[[], None]) -> None:
        event = threading.Event()
        thread = threading.Thread(
            target=target, name=f"stream-job-{job_id}", daemon=True
        )
        with self._lock:
            self._threads[job_id] = thread
            self._cancel[job_id] = event
        thread.start()

    def request_cancel(self, job_id: str) -> None:
        with self._lock:
            event = self._cancel.get(job_id)
        if event is not None:
            event.set()

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            event = self._cancel.get(job_id)
        return event is not None and event.is_set()

    def is_running(self, job_id: str) -> bool:
        with self._lock:
            thread = self._threads.get(job_id)
        return bool(thread and thread.is_alive())

    def _discard(self, job_id: str) -> None:
        with self._lock:
            self._threads.pop(job_id, None)
            self._cancel.pop(job_id, None)

    def reset(self) -> None:
        """测试辅助：等待并清空全部在跑作业。"""
        with self._lock:
            threads = list(self._threads.items())
            for job_id, event in self._cancel.items():
                event.set()
        for job_id, thread in threads:
            thread.join(timeout=30)
        with self._lock:
            self._threads.clear()
            self._cancel.clear()


registry = JobRegistry()


# ---------- 逐行解析 ----------


class StreamFormatError(ValueError):
    def __init__(self, message: str, *, line: int) -> None:
        super().__init__(message)
        self.line = line


def _decode_line(raw: bytes, line_no: int) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StreamFormatError(
            f"NDJSON 第 {line_no} 行不是合法 UTF-8：{exc.reason}", line=line_no
        ) from exc


def _parse_line(raw: bytes, line_no: int) -> Any:
    text = _decode_line(raw, line_no).strip()
    if not text:
        return None  # 空行/纯空白行：跳过，不占记录序号
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise StreamFormatError(
            f"NDJSON 第 {line_no} 行解析失败：{exc.msg}", line=line_no
        ) from exc


# ---------- 测试钩子 ----------

# 处理每条记录前回调 (job_id, line_no)；测试可注入用于制造取消/崩溃时序。
on_record_hook: Callable[[str, int], None] | None = None
# 成品文件已 rename 发布、数据库 succeeded 事务尚未写入时回调 (job_id)。
# 测试注入后抛 BaseException 可精确模拟该窗口内的硬崩溃。
on_publish_hook: Callable[[str], None] | None = None


# ---------- 发布对账（崩溃恢复） ----------


def _published_file_is_valid(path: Path, expected_records: int) -> bool:
    """成品文件必须是可逐行解析的 NDJSON，且记录数与检查点一致。"""
    if not path.is_file() or path.stat().st_size == 0:
        return False
    count = 0
    try:
        with open(path, "rb") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    return False
                json.loads(line.decode("utf-8"))
                count += 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return count == expected_records


def reconcile_published_job(db: Database, job_id: str) -> bool:
    """处理“成品已发布、succeeded 事务未提交”的崩溃窗口。

    仅在数据库仍是 queued/running 时对账：成品存在且是完整可解析的 NDJSON
    （记录数等于已检查点记录数）时补登 succeeded 并清理原始文件；否则不动，
    交由正常检查点续跑逻辑处理。
    """
    job = db.get_stream_job(job_id)
    if job is None or job.status not in ("queued", "running"):
        return False
    published = final_output_path(job_id)
    if not published.is_file():
        return False
    if not _published_file_is_valid(published, job.records_processed):
        # 成品意外存在但不可信：隔离，绝不让它与未完成状态并存
        published.unlink(missing_ok=True)
        return False
    db.reconcile_published_stream_job(job_id, output_filename=published.name)
    raw_path(job_id).unlink(missing_ok=True)
    partial_output_path(job_id).unlink(missing_ok=True)
    return True


def cleanup_terminal_leftovers(db: Database, job_id: str) -> None:
    """终态作业（正常路径或遗留线程）只允许保留已发布成品，其余临时文件清掉。"""
    raw_path(job_id).unlink(missing_ok=True)
    partial_output_path(job_id).unlink(missing_ok=True)


# ---------- worker ----------


def run_stream_job(job_id: str, get_db: Callable[[], Database],
                   get_key: Callable[[], MasterKey]) -> None:
    """执行（或从安全检查点续跑）一个流式作业。"""
    db = get_db()
    # 优先对账“成品已发布但状态未提交”的崩溃窗口：补登 succeeded 后直接退出
    if reconcile_published_job(db, job_id):
        # 崩溃可能发生在凭证发布之前：对账补登的同时确保凭证存在
        publish_stream_receipt(db, get_key(), job_id,
                               output_path=final_output_path(job_id))
        registry._discard(job_id)
        return
    job = db.get_stream_job(job_id)
    if job is None:
        registry._discard(job_id)
        return
    # 已终结（并发终结竞争）：不重复处理，只清理遗留临时文件后退出
    if job.status not in ("queued", "running"):
        cleanup_terminal_leftovers(db, job_id)
        registry._discard(job_id)
        return

    try:
        strategy = Strategy.model_validate_json(
            db.get_stream_strategy_json(job_id) or "{}"
        )
    except Exception as exc:  # 策略在创建时已校验，这里只做防御
        db.mark_stream_failed(job_id, message=f"策略无法加载：{exc}", line=None)
        cleanup_stream_files(job_id, keep_output=False)
        registry._discard(job_id)
        return

    src = raw_path(job_id)
    if not src.exists():
        db.mark_stream_failed(job_id, message="原始上传文件已不存在，无法处理", line=None)
        cleanup_stream_files(job_id, keep_output=False)
        registry._discard(job_id)
        return

    # 重启前已请求取消：不做任何新处理
    if db.stream_cancel_requested(job_id) or registry.is_cancelled(job_id):
        db.mark_stream_cancelled(job_id)
        cleanup_stream_files(job_id, keep_output=False)
        registry._discard(job_id)
        return

    # 沿用作业创建时的令牌关联域：上下文原文不持久化，凭域标识恢复子密钥
    domain_id = db.get_stream_domain_id(job_id)
    token_key, _domain_fp, _ = resolve_token_domain(
        get_key(), domain_id=domain_id
    )
    engine = RedactionEngine(strategy, token_key, is_ndjson=True,
                             domain_fingerprint=domain_fingerprint(domain_id))

    # 从安全检查点恢复：偏移、计数与统计
    pos = job.bytes_processed
    record_idx = job.records_processed
    fields_scanned = job.fields_scanned
    by_action = dict(job.by_action)
    by_rule = dict(job.by_rule)
    audit_total = job.audit_count
    risk_total = job.risk_count
    engine.risk_base = risk_total

    partial = partial_output_path(job_id)
    partial.parent.mkdir(parents=True, exist_ok=True)

    # 截断到已检查点字节：严格丢弃未随事务提交的输出（fsync 在提交之前完成，
    # 因此已提交的每个输出字节必然已在盘上）。
    # 守卫：partial 缺失/小于检查点字节时，open(...,'a+b') + truncate 会产生
    # NUL 填充的损坏文件；这种状态无法安全续跑，直接判失败并清理。
    if partial.exists():
        partial_size = partial.stat().st_size
        if partial_size < job.output_bytes:
            db.mark_stream_failed(
                job_id,
                message=(f"未完成输出文件损坏（{partial_size} 字节，少于检查点 "
                         f"{job.output_bytes} 字节），无法从检查点继续"),
                line=None,
            )
            cleanup_stream_files(job_id, keep_output=False)
            registry._discard(job_id)
            return
    elif job.output_bytes:
        db.mark_stream_failed(
            job_id, message="未完成输出文件丢失，无法从检查点继续", line=None
        )
        cleanup_stream_files(job_id, keep_output=False)
        registry._discard(job_id)
        return

    out = open(partial, "a+b", buffering=0)
    out.truncate(job.output_bytes)
    out.seek(0, os.SEEK_END)

    pending_audit: list[AuditEntry] = []
    pending_risks: list[RiskFinding] = []
    pending_issues: list[DecodeIssue] = []
    since_checkpoint = 0
    last_line_no = job.last_line_no
    # 引擎每轮（含本进程内续跑）从零计数 fields_scanned，需要加上检查点基线
    fields_base = fields_scanned
    cancelled = False
    failed: tuple[str, int | None] | None = None

    def write_checkpoint() -> None:
        """先 fsync 输出，再提交数据库检查点（崩溃安全顺序）。"""
        nonlocal audit_total, risk_total, issue_total
        out.flush()
        os.fsync(out.fileno())
        output_bytes = out.tell()
        db.checkpoint_stream_job(
            job_id,
            bytes_processed=pos,
            records_processed=record_idx,
            audit_count=audit_total + len(pending_audit),
            risk_count=risk_total + len(pending_risks),
            fields_scanned=fields_scanned,
            by_action=by_action,
            by_rule=by_rule,
            last_line_no=last_line_no,
            output_bytes=output_bytes,
            audit=pending_audit,
            risks=pending_risks,
            decode_issues=pending_issues,
            decode_issue_count=issue_total + len(pending_issues),
        )
        audit_total += len(pending_audit)
        risk_total += len(pending_risks)
        issue_total += len(pending_issues)
        pending_audit.clear()
        pending_risks.clear()
        pending_issues.clear()

    try:
        with open(src, "rb") as fh:
            fh.seek(pos)
            for raw in fh:
                line_no = last_line_no + 1
                last_line_no = line_no
                pos += len(raw)

                if on_record_hook is not None:
                    on_record_hook(job_id, line_no)

                # 取消点：停在下一安全检查点边界（本批开始处）
                if db.stream_cancel_requested(job_id) or registry.is_cancelled(job_id):
                    # 该行尚未处理，回退行/字节计数，恢复时从这里重新读
                    pos -= len(raw)
                    last_line_no = line_no - 1
                    cancelled = True
                    break

                try:
                    record = _parse_line(raw, line_no)
                except StreamFormatError as exc:
                    # 出错行尚未输出、尚未计数；回退行/字节计数后终止
                    pos -= len(raw)
                    last_line_no = line_no - 1
                    failed = (str(exc), exc.line)
                    break
                if record is None:
                    # 空行：不是记录，不推进 record_idx，也不触发检查点
                    continue
                redacted = engine.process_record(record, record_idx, line_no=line_no)
                out.write(
                    (json.dumps(redacted, ensure_ascii=False) + "\n").encode("utf-8")
                )
                record_idx += 1

                new_audit, new_risks = engine.drain_events()
                if new_audit:
                    pending_audit.extend(new_audit)
                    for a in new_audit:
                        by_action[a.action] = by_action.get(a.action, 0) + 1
                        by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
                pending_risks.extend(new_risks)
                # 引擎本轮从零计数，基线为本次 worker 启动时的检查点累计
                fields_scanned = fields_base + engine.fields_scanned
                since_checkpoint += 1

                if since_checkpoint >= checkpoint_records():
                    write_checkpoint()
                    since_checkpoint = 0

            if not cancelled and failed is None:
                # 空文件/全空行：与小批量接口一致，拒绝空批次
                if record_idx == 0:
                    failed = ("日志批次为空（没有任何非空行）", None)
    except OSError as exc:
        failed = (f"读取/写入文件失败：{exc}", last_line_no or None)
    except Exception as exc:  # 防御：任何意外都要把作业置为终态并清理
        failed = (f"处理失败：{exc}", last_line_no or None)

    # ---- 终结 ----
    try:
        if failed is not None:
            message, line = failed
            try:
                if since_checkpoint:
                    write_checkpoint()
            except Exception:
                pass
            db.mark_stream_failed(job_id, message=message, line=line)
            cleanup_stream_files(job_id, keep_output=False)
        elif cancelled:
            try:
                if since_checkpoint:
                    write_checkpoint()
            except Exception:
                pass
            db.mark_stream_cancelled(job_id)
            cleanup_stream_files(job_id, keep_output=False)
        else:
            # 成功：最终检查点包含全部尾部事件，然后原子发布
            write_checkpoint()
            out.flush()
            os.fsync(out.fileno())
            out.close()
            published = final_output_path(job_id)
            atomic_publish(partial, published)
            # 测试钩子：精确模拟“成品已发布、succeeded 事务未提交”的崩溃窗口
            if on_publish_hook is not None:
                on_publish_hook(job_id)
            # 完整性凭证随成品一同发布（崩溃窗口由恢复对账补发）
            publish_stream_receipt(db, get_key(), job_id, output_path=published)
            # 先清理原始文件，再发布终态：调用方看到 succeeded 时
            # 作业目录必须已经收拾干净（崩溃则由恢复对账重复清理，幂等）
            raw_path(job_id).unlink(missing_ok=True)
            db.mark_stream_succeeded(
                job_id, output_filename=published.name
            )
    finally:
        if not out.closed:
            out.close()

    registry._discard(job_id)


# ---------- 重启恢复 ----------


_recovery_lock = threading.Lock()
_recovery_done = False


def recover_stream_jobs(get_db: Callable[[], Database],
                        get_key: Callable[[], MasterKey]) -> None:
    """服务启动后恢复所有 queued/running 作业（含持久化取消意图）。

    幂等：只执行一次；测试通过 :func:`reset_recovery` 重置。
    """
    global _recovery_done
    with _recovery_lock:
        if _recovery_done:
            return
        _recovery_done = True

    ensure_stream_dirs()
    db = get_db()
    for row in db.resumable_stream_jobs():
        job_id = row["id"]
        if registry.is_running(job_id):
            continue
        # 1) 先对账“成品已发布、状态未提交”的崩溃窗口：补登 succeeded，
        #    绝不能在这种状态下再开一个会写 NUL partial 的 worker
        if reconcile_published_job(db, job_id):
            # 对账补登的同时确保完整性凭证存在（崩溃可能发生在凭证发布前）
            publish_stream_receipt(db, get_key(), job_id,
                                   output_path=final_output_path(job_id))
            continue
        # 2) 原始文件已丢失（如手工清理）：无法续跑，标记失败并清理残留输出
        if not raw_path(job_id).exists():
            db.mark_stream_failed(
                job_id, message="服务重启后原始上传文件已丢失，无法继续处理", line=None
            )
            cleanup_stream_files(job_id, keep_output=False)
            continue
        # 3) 正常从安全检查点续跑（含重启前已持久化的取消意图）
        registry.start(job_id, lambda jid=job_id: run_stream_job(jid, get_db, get_key))


def reset_recovery() -> None:
    """测试辅助：允许再次触发恢复扫描。"""
    global _recovery_done
    with _recovery_lock:
        _recovery_done = False
