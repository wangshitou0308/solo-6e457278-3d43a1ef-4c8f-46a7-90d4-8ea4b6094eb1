"""诊断包（ZIP）脱敏作业：逐文件处理、文件级安全检查点、取消与重启恢复。

设计要点
--------
* 上传的压缩包以 **0600** 落盘到 ``bundles/raw/``；worker 用 zipfile 流式
  读取条目，**不把整包读入内存**；每个文件的脱敏输出先写暂存区临时文件，
  fsync 并原子 rename 到 ``bundles/staging/{id}/<相对路径>`` 后，才在
  **同一 SQLite 事务**提交该文件的结果行、进度与审计/风险（文件级检查点）。
* 结构化文件（.json/.ndjson）走完整字段+内容规则；纯文本（.log/.txt）按行
  只应用内容规则；输出沿用包内相对路径，并**保留原换行风格**（CRLF/LF
  逐行保留，JSON 重序列化按源文件探测的换行风格输出）。
* 二进制与不支持类型不写入结果，只在清单 ``redaction-manifest.json`` 列明
  原因；单文件解析失败同理（file 级 failed），不影响其他文件。
* 取消意图同时保存在内存事件与数据库（``cancel_requested``），重启后仍生效；
  重启后凭 ``bundle_files`` 跳过已完成文件，从未完成的第一个文件继续。
* 全部文件完成后把暂存文件与清单打成结果 ZIP，原子 rename 发布到
  ``bundles/out/{id}.zip``；原始压缩包在成功/失败/取消后一律删除。
"""
from __future__ import annotations

import codecs
import io
import json
import os
import shutil
import stat
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from . import config
from .bundle_zip import (
    MANIFEST_NAME,
    BundleEntry,
    BundleRejection,
    max_file_bytes,
    max_total_bytes,
    validate_bundle,
)
from .crypto import MasterKey
from .database import Database, utcnow_iso
from .engine import RedactionEngine
from .models import BundleFileInfo, BundleJobModel, Strategy
from .stream_jobs import JobRegistry, _fsync_dir, atomic_publish, tighten

# 结果 ZIP 内每个条目的权限（仅属主可读写）
_ZIP_FILE_MODE = 0o600
# 逐行读取包内条目时的缓冲大小
_READ_BUFFER = 64 * 1024
# 二进制嗅探：头部出现 NUL 字节即视为二进制
_SNIFF_BYTES = 8192
# 暂存/发布临时文件前缀（恢复时清理同名前缀的孤儿临时文件）
_TMP_PREFIX = ".tmp-"


def bundles_dir() -> Path:
    return config.settings.data_dir / "bundles"


def raw_path(job_id: str) -> Path:
    return bundles_dir() / "raw" / f"{job_id}.zip"


def staging_dir(job_id: str) -> Path:
    return bundles_dir() / "staging" / job_id


def final_output_path(job_id: str) -> Path:
    return bundles_dir() / "out" / f"{job_id}.zip"


def ensure_bundle_dirs() -> None:
    for d in (bundles_dir() / "raw", bundles_dir() / "staging", bundles_dir() / "out"):
        d.mkdir(parents=True, exist_ok=True)


def cleanup_bundle_files(job_id: str, *, keep_output: bool) -> None:
    """作业终结清理：原始压缩包与暂存区必删；未发布成功时输出一并删除。"""
    raw_path(job_id).unlink(missing_ok=True)
    shutil.rmtree(staging_dir(job_id), ignore_errors=True)
    if not keep_output:
        final_output_path(job_id).unlink(missing_ok=True)
        (bundles_dir() / "out" / f"{_TMP_PREFIX}{job_id}.zip").unlink(missing_ok=True)


# 进程内取消注册表（与流式作业同款，独立实例互不影响）
bundle_registry = JobRegistry()

# ---------- 测试钩子 ----------

# 处理每个条目前回调 (job_id, path)；测试可注入用于制造取消/崩溃时序。
on_file_hook: Callable[[str, str], None] | None = None
# 成品 ZIP 已 rename 发布、数据库 succeeded 事务尚未写入时回调 (job_id)。
on_publish_hook: Callable[[str], None] | None = None


# ---------- 条目分类与处理 ----------


class _EntryError(Exception):
    """单文件处理失败：写入清单原因后继续处理其他文件。"""


class _LimitExceeded(Exception):
    """实际解压字节超过上限（压缩包尺寸头造假）：整个作业失败。"""


class _BundleCancelled(Exception):
    """处理过程中收到取消意图。"""


class _ByteBudget:
    """本次 worker 运行累计解压字节；防御伪造尺寸的压缩包。"""

    def __init__(self) -> None:
        self.total = 0

    def add(self, n: int) -> None:
        self.total += n
        if self.total > max_total_bytes():
            raise _LimitExceeded(
                f"实际解压总量超过上限（{max_total_bytes()} 字节），"
                "压缩包尺寸头不可信"
            )


def _classify(name: str) -> str | None:
    """按扩展名归类：json / ndjson / text；不支持的类型返回 None。"""
    suffix = PurePosixPath(name).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".ndjson":
        return "ndjson"
    if suffix in (".log", ".txt"):
        return "text"
    return None


def _sniff_binary(zf: zipfile.ZipFile, entry: BundleEntry) -> bool:
    with zf.open(entry.info) as fh:
        head = fh.read(_SNIFF_BYTES)
    return b"\x00" in head


def _split_ending(raw: bytes) -> tuple[bytes, bytes]:
    """拆出一行的内容与原始换行符（CRLF/LF/孤立 CR/无换行）。"""
    if raw.endswith(b"\r\n"):
        return raw[:-2], b"\r\n"
    if raw.endswith(b"\n"):
        return raw[:-1], b"\n"
    if raw.endswith(b"\r"):
        return raw[:-1], b"\r"
    return raw, b""


def _detect_newline(raw: bytes) -> str:
    """探测源文件的换行风格（以首个换行为准），供 JSON 重序列化沿用。"""
    idx = raw.find(b"\n")
    if idx > 0 and raw[idx - 1 : idx] == b"\r":
        return "\r\n"
    return "\n"


def _decode(body: bytes, line_no: int) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _EntryError(f"第 {line_no} 行不是合法 UTF-8：{exc.reason}") from exc


def _open_staged_tmp(staging: Path):
    """以 0600 权限新建暂存临时文件，返回 (路径, 文件对象)。"""
    tmp = staging / f"{_TMP_PREFIX}{uuid.uuid4().hex}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return tmp, os.fdopen(fd, "wb")


def _staged_target(staging: Path, relpath: str) -> Path:
    """暂存落位路径；双保险校验不越出暂存根目录（validate 已保证）。"""
    root = os.path.realpath(staging)
    target = os.path.realpath(staging / relpath)
    if target != root and not target.startswith(root + os.sep):
        raise _EntryError("非法输出路径")
    return Path(target)


def _process_json_entry(
    zf: zipfile.ZipFile,
    entry: BundleEntry,
    engine: RedactionEngine,
    staging: Path,
    budget: _ByteBudget,
    check_cancel: Callable[[], None],
) -> BundleFileInfo:
    """整个 JSON 文档解析后按记录脱敏，重序列化保留顶层结构与换行风格。"""
    limit = max_file_bytes()
    with zf.open(entry.info) as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        raise _LimitExceeded(
            f"{entry.name!r} 实际解压超过单文件上限（{limit} 字节），尺寸头不可信"
        )
    budget.add(len(raw))

    bom = raw.startswith(codecs.BOM_UTF8)
    try:
        text = raw.decode("utf-8-sig" if bom else "utf-8")
    except UnicodeDecodeError as exc:
        raise _EntryError(f"无法按 UTF-8 解码：{exc.reason}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _EntryError(
            f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
        ) from exc

    engine.is_ndjson = False
    was_array = isinstance(data, list)
    records = data if was_array else [data]
    out_records: list[Any] = []
    for idx, record in enumerate(records):
        check_cancel()
        out_records.append(engine.process_record(record, idx))
    out_obj: Any = out_records if was_array else out_records[0]

    serialized = json.dumps(out_obj, ensure_ascii=False, indent=2)
    newline = _detect_newline(raw)
    if newline == "\r\n":
        serialized = serialized.replace("\n", "\r\n")
    payload = (codecs.BOM_UTF8 if bom else b"") + (
        serialized + newline
    ).encode("utf-8")

    tmp, out = _open_staged_tmp(staging)
    try:
        out.write(payload)
        out.flush()
        os.fsync(out.fileno())
    except Exception:
        out.close()
        tmp.unlink(missing_ok=True)
        raise
    out.close()
    return BundleFileInfo(
        path=entry.name, status="redacted", format="json",
        records=len(records), size_in=len(raw), size_out=len(payload),
        output_path=entry.name,
    ), tmp


def _iter_lines(zf: zipfile.ZipFile, entry: BundleEntry, budget: _ByteBudget):
    """逐行产出 (原始行字节, 行号)；同时累计解压字节并执行上限。"""
    limit = max_file_bytes()
    size_in = 0
    with zf.open(entry.info) as fh:
        reader = io.BufferedReader(fh, buffer_size=_READ_BUFFER)
        line_no = 0
        for raw in reader:
            line_no += 1
            size_in += len(raw)
            if size_in > limit:
                raise _LimitExceeded(
                    f"{entry.name!r} 实际解压超过单文件上限（{limit} 字节），"
                    "尺寸头不可信"
                )
            budget.add(len(raw))
            yield raw, line_no


def _process_ndjson_entry(
    zf: zipfile.ZipFile,
    entry: BundleEntry,
    engine: RedactionEngine,
    staging: Path,
    budget: _ByteBudget,
    check_cancel: Callable[[], None],
) -> BundleFileInfo:
    """逐行解析 NDJSON 并脱敏；空白行原样保留（审计行号与物理行对齐）。"""
    engine.is_ndjson = True
    tmp, out = _open_staged_tmp(staging)
    records = 0
    lines = 0
    size_in = 0
    first = True
    try:
        for raw, line_no in _iter_lines(zf, entry, budget):
            lines = line_no
            size_in += len(raw)
            check_cancel()
            body, ending = _split_ending(raw)
            if first:
                first = False
                if body.startswith(codecs.BOM_UTF8):
                    # BOM 原样保留到输出，解析时剥掉
                    out.write(codecs.BOM_UTF8)
                    body = body[len(codecs.BOM_UTF8):]
            text = _decode(body, line_no)
            if not text.strip():
                out.write(body + ending)  # 空白行原样保留
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise _EntryError(
                    f"第 {line_no} 行 JSON 解析失败：{exc.msg}"
                ) from exc
            redacted = engine.process_record(record, records, line_no=line_no)
            out.write(json.dumps(redacted, ensure_ascii=False).encode("utf-8") + ending)
            records += 1
        out.flush()
        os.fsync(out.fileno())
    except Exception:
        # 失败/取消的半成品临时文件绝不落位
        out.close()
        tmp.unlink(missing_ok=True)
        raise
    out.close()
    return BundleFileInfo(
        path=entry.name, status="redacted", format="ndjson",
        records=records, lines=lines, size_in=size_in,
        output_path=entry.name,
    ), tmp


def _process_text_entry(
    zf: zipfile.ZipFile,
    entry: BundleEntry,
    engine: RedactionEngine,
    staging: Path,
    budget: _ByteBudget,
    check_cancel: Callable[[], None],
) -> BundleFileInfo:
    """纯文本按行只应用内容规则；逐行保留原换行符，行数与源文件一致。"""
    engine.is_ndjson = True
    tmp, out = _open_staged_tmp(staging)
    lines = 0
    size_in = 0
    first = True
    try:
        for raw, line_no in _iter_lines(zf, entry, budget):
            lines = line_no
            size_in += len(raw)
            check_cancel()
            body, ending = _split_ending(raw)
            if first:
                first = False
                if body.startswith(codecs.BOM_UTF8):
                    out.write(codecs.BOM_UTF8)
                    body = body[len(codecs.BOM_UTF8):]
            text = _decode(body, line_no)
            redacted = engine.process_text_line(text, line_no - 1, line_no=line_no)
            out.write(redacted.encode("utf-8") + ending)
        out.flush()
        os.fsync(out.fileno())
    except Exception:
        # 失败/取消的半成品临时文件绝不落位
        out.close()
        tmp.unlink(missing_ok=True)
        raise
    out.close()
    return BundleFileInfo(
        path=entry.name, status="redacted", format="text",
        lines=lines, size_in=size_in, output_path=entry.name,
    ), tmp


def _process_entry(
    zf: zipfile.ZipFile,
    entry: BundleEntry,
    engine: RedactionEngine,
    staging: Path,
    budget: _ByteBudget,
    check_cancel: Callable[[], None],
) -> tuple[BundleFileInfo, Path | None]:
    """处理一个条目，返回 (清单行, 暂存临时文件)；跳过/失败时后者为 None。

    可能抛出 _EntryError（单文件失败，调用方转清单）、_LimitExceeded
    （整作业失败）与 _BundleCancelled。
    """
    name = entry.name
    fmt = _classify(name)
    declared = entry.info.file_size
    if name == MANIFEST_NAME:
        return BundleFileInfo(
            path=name, status="skipped", format=fmt, size_in=declared,
            reason=f"文件名与结果清单保留名（{MANIFEST_NAME}）冲突",
        ), None
    if fmt is None:
        return BundleFileInfo(
            path=name, status="skipped", size_in=declared,
            reason="不支持的文件类型（仅处理 .json/.ndjson/.log/.txt）",
        ), None
    if _sniff_binary(zf, entry):
        return BundleFileInfo(
            path=name, status="skipped", format=fmt, size_in=declared,
            reason="二进制文件（含 NUL 字节），不写入结果",
        ), None
    if fmt == "json":
        return _process_json_entry(zf, entry, engine, staging, budget, check_cancel)
    if fmt == "ndjson":
        return _process_ndjson_entry(zf, entry, engine, staging, budget, check_cancel)
    return _process_text_entry(zf, entry, engine, staging, budget, check_cancel)


# ---------- 清单与发布 ----------


def _zip_datetime(iso: str | None) -> tuple[int, int, int, int, int, int]:
    """ISO 时间戳转 ZIP date_time；非法/过早时回退到 ZIP 纪元。"""
    try:
        dt = datetime.fromisoformat(iso or "")
        if dt.year >= 1980:
            return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    except ValueError:
        pass
    return (1980, 1, 1, 0, 0, 0)


def build_manifest(
    job: BundleJobModel, files: list[BundleFileInfo], *, completed_at: str | None
) -> dict[str, Any]:
    """汇总清单内容（不含任何原始值）；成功发布与 /manifest 接口共用。"""
    redacted = sum(1 for f in files if f.status == "redacted")
    skipped = sum(1 for f in files if f.status == "skipped")
    failed = sum(1 for f in files if f.status == "failed")
    return {
        "job_id": job.id,
        "created_at": job.created_at,
        "completed_at": completed_at,
        "strategy_name": job.strategy_name,
        "strategy_version": job.strategy_version,
        "source_filename": job.source_filename,
        "source_sha256": job.content_sha256,
        "key_fingerprint": job.key_fingerprint,
        "stats": {
            "files_total": job.files_total,
            "files_redacted": redacted,
            "files_skipped": skipped,
            "files_failed": failed,
            "records_processed": job.records_processed,
            "fields_scanned": job.fields_scanned,
            "audit_entries": job.audit_count,
            "risk_findings": job.risk_count,
            "by_action": job.by_action,
            "by_rule": job.by_rule,
        },
        "files": [f.model_dump(mode="json") for f in files],
    }


def _write_result_zip(job: BundleJobModel, files: list[BundleFileInfo],
                      manifest: dict[str, Any], tmp_out: Path) -> None:
    """把暂存的脱敏文件与清单写入结果 ZIP（仅含这两类内容）。"""
    entry_time = _zip_datetime(job.created_at)
    staging = staging_dir(job.id)
    with zipfile.ZipFile(tmp_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            if f.status != "redacted" or f.output_path is None:
                continue
            zi = zipfile.ZipInfo(f.output_path, date_time=entry_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = _ZIP_FILE_MODE << 16
            with zf.open(zi, "w") as dest, open(staging / f.path, "rb") as src:
                shutil.copyfileobj(src, dest, 1024 * 1024)
        mi = zipfile.ZipInfo(MANIFEST_NAME, date_time=_zip_datetime(utcnow_iso()))
        mi.compress_type = zipfile.ZIP_DEFLATED
        mi.external_attr = _ZIP_FILE_MODE << 16
        with zf.open(mi, "w") as dest:
            dest.write(
                (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
                .encode("utf-8")
            )
    # ZipFile 关闭只写中央目录，显式 fsync 后再原子发布
    fd = os.open(str(tmp_out), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _published_zip_valid(path: Path, job_id: str) -> bool:
    """成品 ZIP 必须可完整解压校验，且清单 job_id 与本作业一致。"""
    try:
        with zipfile.ZipFile(path) as zf:
            if zf.testzip() is not None:
                return False
            with zf.open(MANIFEST_NAME) as fh:
                manifest = json.loads(fh.read().decode("utf-8"))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return False
    return manifest.get("job_id") == job_id


def reconcile_published_bundle(db: Database, job_id: str) -> bool:
    """处理“成品已发布、succeeded 事务未提交”的崩溃窗口。

    仅在数据库仍是 queued/running 时对账：成品存在且可信（ZIP 完整、清单
    job_id 匹配）时补登 succeeded 并清理原始包与暂存区；否则删除可疑成品，
    交由正常续跑逻辑处理。
    """
    job = db.get_bundle_job(job_id)
    if job is None or job.status not in ("queued", "running"):
        return False
    published = final_output_path(job_id)
    if not published.is_file():
        return False
    if not _published_zip_valid(published, job_id):
        published.unlink(missing_ok=True)
        return False
    db.reconcile_published_bundle_job(
        job_id, output_filename=published.name,
        output_bytes=published.stat().st_size,
    )
    raw_path(job_id).unlink(missing_ok=True)
    shutil.rmtree(staging_dir(job_id), ignore_errors=True)
    return True


# ---------- worker ----------


def run_bundle_job(job_id: str, get_db: Callable[[], Database],
                   get_key: Callable[[], MasterKey]) -> None:
    """执行（或从文件级检查点续跑）一个诊断包作业。"""
    db = get_db()
    # 优先对账“成品已发布但状态未提交”的崩溃窗口：补登 succeeded 后直接退出
    if reconcile_published_bundle(db, job_id):
        bundle_registry._discard(job_id)
        return
    job = db.get_bundle_job(job_id)
    if job is None:
        bundle_registry._discard(job_id)
        return
    # 已终结（并发终结竞争）：不重复处理，只清理遗留临时文件后退出
    if job.status not in ("queued", "running"):
        cleanup_bundle_files(job_id, keep_output=job.status == "succeeded")
        bundle_registry._discard(job_id)
        return

    try:
        strategy = Strategy.model_validate_json(
            db.get_bundle_strategy_json(job_id) or "{}"
        )
    except Exception as exc:  # 策略在创建时已校验，这里只做防御
        db.mark_bundle_failed(job_id, message=f"策略无法加载：{exc}")
        cleanup_bundle_files(job_id, keep_output=False)
        bundle_registry._discard(job_id)
        return

    src = raw_path(job_id)
    if not src.exists():
        db.mark_bundle_failed(job_id, message="原始压缩包已不存在，无法处理")
        cleanup_bundle_files(job_id, keep_output=False)
        bundle_registry._discard(job_id)
        return

    # 重启前已请求取消：不做任何新处理
    if db.bundle_cancel_requested(job_id) or bundle_registry.is_cancelled(job_id):
        db.mark_bundle_cancelled(job_id)
        cleanup_bundle_files(job_id, keep_output=False)
        bundle_registry._discard(job_id)
        return

    # 重新校验（与上传时同一函数，结果确定）：恢复场景下同样兜底
    try:
        entries = validate_bundle(src)
    except BundleRejection as exc:
        db.mark_bundle_failed(
            job_id, message="压缩包未通过安全校验：" + "；".join(exc.reasons)
        )
        cleanup_bundle_files(job_id, keep_output=False)
        bundle_registry._discard(job_id)
        return
    except Exception as exc:
        db.mark_bundle_failed(job_id, message=f"压缩包无法读取：{exc}")
        cleanup_bundle_files(job_id, keep_output=False)
        bundle_registry._discard(job_id)
        return

    engine = RedactionEngine(strategy, get_key())
    engine.risk_base = job.risk_count

    # 从文件级检查点恢复：已完成文件直接跳过（审计/风险不会重复落库）
    done = db.bundle_done_files(job_id)
    files_processed = job.files_processed
    records_processed = job.records_processed
    audit_total = job.audit_count
    risk_total = job.risk_count
    fields_base = job.fields_scanned
    fields_scanned = job.fields_scanned
    by_action = dict(job.by_action)
    by_rule = dict(job.by_rule)

    staging = staging_dir(job_id)
    staging.mkdir(parents=True, exist_ok=True)
    os.chmod(staging, 0o700)
    # 清理上次崩溃留下的孤儿临时文件（未随检查点提交，直接丢弃）
    for orphan in staging.glob(f"{_TMP_PREFIX}*"):
        orphan.unlink(missing_ok=True)

    budget = _ByteBudget()
    cancelled = False
    failed: str | None = None

    def check_cancel() -> None:
        if db.bundle_cancel_requested(job_id) or bundle_registry.is_cancelled(job_id):
            raise _BundleCancelled

    try:
        with zipfile.ZipFile(src) as zf:
            for entry in entries:
                if entry.name in done:
                    continue
                if (db.bundle_cancel_requested(job_id)
                        or bundle_registry.is_cancelled(job_id)):
                    cancelled = True
                    break
                if on_file_hook is not None:
                    on_file_hook(job_id, entry.name)
                db.update_bundle_current_file(job_id, entry.name)

                tmp: Path | None = None
                try:
                    file_row, tmp = _process_entry(
                        zf, entry, engine, staging, budget, check_cancel
                    )
                except _BundleCancelled:
                    cancelled = True
                    break
                except _EntryError as exc:
                    # 单文件失败：记入清单原因，继续处理其他文件
                    file_row = BundleFileInfo(
                        path=entry.name, status="failed", reason=str(exc),
                        format=_classify(entry.name),
                        size_in=entry.info.file_size,
                    )

                # 排空本文件的审计/风险并标注来源路径；失败文件的半成品事件
                # 不落库（其输出不会进入结果 ZIP，审计只覆盖结果内容）
                audit, risks = engine.drain_events()
                if file_row.status == "failed":
                    audit, risks = [], []
                file_row.audit_entries = len(audit)
                file_row.risk_findings = len(risks)
                for a in audit:
                    a.source_path = entry.name
                for r in risks:
                    r.source_path = entry.name

                if tmp is not None:
                    # 先原子落位再提交检查点：崩溃后只会重处理，不会缺输出
                    target = _staged_target(staging, entry.name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(tmp, target)
                    tighten(target)
                    _fsync_dir(target.parent)
                    file_row.size_out = target.stat().st_size

                files_processed += 1
                records_processed += file_row.records
                fields_scanned = fields_base + engine.fields_scanned
                for a in audit:
                    by_action[a.action] = by_action.get(a.action, 0) + 1
                    by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
                db.checkpoint_bundle_file(
                    job_id,
                    file_row=file_row,
                    files_processed=files_processed,
                    records_processed=records_processed,
                    audit_count=audit_total + len(audit),
                    risk_count=risk_total + len(risks),
                    fields_scanned=fields_scanned,
                    by_action=by_action,
                    by_rule=by_rule,
                    audit=audit,
                    risks=risks,
                )
                audit_total += len(audit)
                risk_total += len(risks)
    except _LimitExceeded as exc:
        failed = str(exc)
    except (OSError, zipfile.BadZipFile) as exc:
        failed = f"读取压缩包失败：{exc}"
    except Exception as exc:  # 防御：任何意外都要把作业置为终态并清理
        failed = f"处理失败：{exc}"

    # ---- 终结 ----
    if failed is not None:
        db.mark_bundle_failed(job_id, message=failed)
        cleanup_bundle_files(job_id, keep_output=False)
    elif cancelled:
        db.mark_bundle_cancelled(job_id)
        cleanup_bundle_files(job_id, keep_output=False)
    else:
        try:
            job = db.get_bundle_job(job_id)
            files = db.bundle_files_for_manifest(job_id)
            manifest = build_manifest(job, files, completed_at=utcnow_iso())
            tmp_out = bundles_dir() / "out" / f"{_TMP_PREFIX}{job_id}.zip"
            tmp_out.parent.mkdir(parents=True, exist_ok=True)
            _write_result_zip(job, files, manifest, tmp_out)
            published = final_output_path(job_id)
            atomic_publish(tmp_out, published)
            # 测试钩子：精确模拟“成品已发布、succeeded 事务未提交”的崩溃窗口
            if on_publish_hook is not None:
                on_publish_hook(job_id)
            db.mark_bundle_succeeded(
                job_id, output_filename=published.name,
                output_bytes=published.stat().st_size,
            )
            # 原始压缩包与暂存区必须清理；已发布的成品保留
            raw_path(job_id).unlink(missing_ok=True)
            shutil.rmtree(staging_dir(job_id), ignore_errors=True)
        except Exception as exc:  # 发布失败同样进入终态并清理
            db.mark_bundle_failed(job_id, message=f"结果发布失败：{exc}")
            cleanup_bundle_files(job_id, keep_output=False)

    bundle_registry._discard(job_id)


# ---------- 重启恢复 ----------


_recovery_lock = threading.Lock()
_recovery_done = False


def recover_bundle_jobs(get_db: Callable[[], Database],
                        get_key: Callable[[], MasterKey]) -> None:
    """服务启动后恢复所有 queued/running 诊断包作业（含持久化取消意图）。

    幂等：只执行一次；测试通过 :func:`reset_bundle_recovery` 重置。
    """
    global _recovery_done
    with _recovery_lock:
        if _recovery_done:
            return
        _recovery_done = True

    ensure_bundle_dirs()
    db = get_db()
    for row in db.resumable_bundle_jobs():
        job_id = row["id"]
        if bundle_registry.is_running(job_id):
            continue
        # 1) 先对账“成品已发布、状态未提交”的崩溃窗口
        if reconcile_published_bundle(db, job_id):
            continue
        # 2) 原始压缩包已丢失：无法续跑，标记失败并清理残留
        if not raw_path(job_id).exists():
            db.mark_bundle_failed(
                job_id, message="服务重启后原始压缩包已丢失，无法继续处理"
            )
            cleanup_bundle_files(job_id, keep_output=False)
            continue
        # 3) 正常从文件级检查点续跑（含重启前已持久化的取消意图）
        bundle_registry.start(
            job_id, lambda jid=job_id: run_bundle_job(jid, get_db, get_key)
        )


def reset_bundle_recovery() -> None:
    """测试辅助：允许再次触发恢复扫描。"""
    global _recovery_done
    with _recovery_lock:
        _recovery_done = False
