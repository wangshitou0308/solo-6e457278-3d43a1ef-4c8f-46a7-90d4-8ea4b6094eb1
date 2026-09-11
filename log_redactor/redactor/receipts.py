"""脱敏结果完整性凭证（integrity receipt）。

设计要点
--------
* 三类作业（小批量 ``jobs``、流式 ``stream-jobs``、诊断包 ``bundle-jobs``）在
  **成功发布结果**时生成一份独立 JSON 凭证，与结果文件同目录落盘
  （``<job_id>.receipt.json``，0600，临时文件 + 原子 rename 发布）。
* 凭证记录：格式版本、输入与规范化策略摘要、关联域指纹、统计计数与输出文件
  摘要；诊断包另列结果 ZIP 内各文件的路径与摘要。凭证**只含摘要/指纹/计数**，
  不含原始值、处理后值、策略正文或密钥材料。
* 标签：由本地主密钥派生凭证子密钥（独立 HMAC 命名空间，与令牌/关联域密钥
  隔离），对除 ``tag`` 外的全部字段按固定（字典序）键顺序规范化序列化后计算
  HMAC-SHA256。更换主密钥后，旧凭证校验判定为“密钥不匹配”。
* 校验：重算标签与**现有结果文件**的摘要，区分 凭证被改动 / 结果缺失 /
  内容不符 / 密钥不匹配 / 格式不支持；只读文件计算摘要，**不重新脱敏，
  也不返回文件内容**。
* 取消/失败的异步作业不生成凭证；凭证随结果一同原子发布，服务重启后仍可
  校验已发布结果（“成品已发布、凭证未发布”的崩溃窗口由恢复对账补发，
  查询接口发现缺失时也会自愈补发）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .crypto import MasterKey, domain_fingerprint, key_fingerprint
from .database import utcnow_iso
from .models import RunStats

if TYPE_CHECKING:  # 仅类型标注：避免与 stream_jobs/bundle_jobs 形成运行时循环导入
    from .database import Database

#: 凭证格式版本；结构不兼容变更时递增，旧版本校验判定为“格式不支持”
RECEIPT_FORMAT = "redaction-receipt-v1"

#: 作业类型标识（写入凭证，校验时与入口作业类型绑定）
KIND_BATCH = "batch"
KIND_STREAM = "stream"
KIND_BUNDLE = "bundle"

# 凭证子密钥与标签的 HMAC 命名空间（与令牌/关联域派生相互隔离）
_RECEIPT_KEY_NAMESPACE = "receipt-key-v1"
_RECEIPT_TAG_NAMESPACE = "receipt-tag-v1"

# 校验判定（verdict）
VERDICT_OK = "ok"
VERDICT_UNSUPPORTED_FORMAT = "unsupported_format"
VERDICT_KEY_MISMATCH = "key_mismatch"
VERDICT_RECEIPT_TAMPERED = "receipt_tampered"
VERDICT_JOB_MISMATCH = "job_mismatch"
VERDICT_RESULT_MISSING = "result_missing"
VERDICT_CONTENT_MISMATCH = "content_mismatch"

# 校验阶段（checks 字典的键，按执行顺序记录 ok/failed/skipped）
_STAGES = ("format", "binding", "structure", "key", "tag", "result", "content")

_HASH_CHUNK = 1024 * 1024  # 1 MiB，与上传拷贝块一致，不读入整文件


# ---------- 密钥与标签 ----------


def derive_receipt_key(master: MasterKey) -> MasterKey:
    """由本地主密钥派生凭证子密钥（HMAC 派生，不可逆推主密钥）。"""
    return MasterKey(master.digest(_RECEIPT_KEY_NAMESPACE, "receipt-subkey"))


def _canonical_json(receipt: dict[str, Any]) -> str:
    """除 ``tag`` 外全部字段按固定（字典序）键顺序规范化序列化。"""
    payload = {k: v for k, v in receipt.items() if k != "tag"}
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def compute_tag(master: MasterKey, receipt: dict[str, Any]) -> str:
    """对凭证（不含 ``tag`` 字段）按固定字段顺序计算 HMAC-SHA256 标签。"""
    return derive_receipt_key(master).digest(
        _RECEIPT_TAG_NAMESPACE, _canonical_json(receipt)
    ).hex()


# ---------- 摘要 ----------


def sha256_file(path: Path) -> tuple[str, int]:
    """流式计算文件 SHA-256 与字节数（不把整文件读入内存）。"""
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def zip_entry_digests(path: Path) -> list[dict[str, Any]]:
    """结果 ZIP 内各文件（脱敏文件与清单）的路径、内容 SHA-256 与解压后字节数。

    按路径排序返回，与凭证内列表可直接做顺序无关的等值比较。
    """
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            digest = hashlib.sha256()
            total = 0
            with zf.open(info) as fh:
                for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
                    digest.update(chunk)
                    total += len(chunk)
            entries.append(
                {"path": info.filename, "sha256": digest.hexdigest(), "bytes": total}
            )
    return sorted(entries, key=lambda e: e["path"])


# ---------- 生成 ----------


def receipt_path_for_output(output_path: Path) -> Path:
    """凭证与结果文件同目录：``<job_id>.receipt.json``。"""
    return output_path.parent / f"{output_path.stem}.receipt.json"


def batch_stats(stats: RunStats) -> dict[str, Any]:
    """小批量作业统计计数（RunStats → 凭证 stats 段）。"""
    return {
        "records": stats.records_in,
        "fields_scanned": stats.fields_scanned,
        "audit_entries": stats.audit_entries,
        "risk_findings": stats.risk_findings,
        "by_action": dict(stats.by_action),
        "by_rule": dict(stats.by_rule),
    }


def build_receipt(
    master: MasterKey,
    *,
    job_id: str,
    job_kind: str,
    input_sha256: str,
    input_bytes: int | None,
    strategy_name: str,
    strategy_version: str,
    strategy_sha256: str,
    domain_fingerprint: str,
    stats: dict[str, Any],
    output_filename: str,
    output_format: str,
    output_sha256: str,
    output_bytes: int,
    files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """组装凭证并签名。只接收摘要/指纹/计数，绝不接收原始值或策略正文。"""
    input_section: dict[str, Any] = {"sha256": input_sha256}
    if input_bytes is not None:
        input_section["bytes"] = input_bytes
    receipt: dict[str, Any] = {
        "format": RECEIPT_FORMAT,
        "receipt_id": uuid.uuid4().hex,
        "job_id": job_id,
        "job_kind": job_kind,
        "created_at": utcnow_iso(),
        "key_fingerprint": key_fingerprint(master),
        "domain_fingerprint": domain_fingerprint,
        "input": input_section,
        "strategy": {
            "name": strategy_name,
            "version": strategy_version,
            "sha256": strategy_sha256,
        },
        "stats": stats,
        "output": {
            "filename": output_filename,
            "format": output_format,
            "sha256": output_sha256,
            "bytes": output_bytes,
        },
    }
    if files is not None:
        receipt["files"] = sorted(files, key=lambda f: f["path"])
    receipt["tag"] = compute_tag(master, receipt)
    return receipt


def _fsync_dir(path: Path) -> None:
    """fsync 目录，保证 rename 落盘（失败时静默，属尽力而为）。"""
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """原子发布凭证文件：0600 临时文件 + fsync + rename + fsync 目录。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".tmp-receipt-{uuid.uuid4().hex}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        _fsync_dir(path.parent)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def read_receipt(path: Path) -> dict[str, Any] | None:
    """读取凭证文件；不存在/损坏时返回 None（由调用方决定补发或报错）。"""
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# ---------- 三类作业的凭证生成与补发 ----------


def publish_batch_receipt(
    master: MasterKey,
    *,
    job_id: str,
    fmt: str,
    content_sha256: str,
    content_bytes: int,
    strategy_name: str,
    strategy_version: str,
    strategy_sha256: str,
    domain_fingerprint: str,
    stats: dict[str, Any],
    output_path: Path,
) -> dict[str, Any]:
    """小批量作业：创建路径用内存中的数据生成并发布凭证。"""
    sha, size = sha256_file(output_path)
    receipt = build_receipt(
        master,
        job_id=job_id,
        job_kind=KIND_BATCH,
        input_sha256=content_sha256,
        input_bytes=content_bytes,
        strategy_name=strategy_name,
        strategy_version=strategy_version,
        strategy_sha256=strategy_sha256,
        domain_fingerprint=domain_fingerprint,
        stats=stats,
        output_filename=output_path.name,
        output_format=fmt,
        output_sha256=sha,
        output_bytes=size,
    )
    write_receipt(receipt_path_for_output(output_path), receipt)
    return receipt


def ensure_batch_receipt(
    db: "Database", master: MasterKey, job_id: str, *, output_path: Path
) -> bool:
    """小批量作业凭证缺失时按持久化记录补发；已存在则跳过（幂等）。"""
    path = receipt_path_for_output(output_path)
    if path.exists():
        return True
    row = db.get_job_receipt_source(job_id)
    if row is None or not output_path.exists():
        return False
    return bool(
        publish_batch_receipt(
            master,
            job_id=job_id,
            fmt=row["format"],
            content_sha256=row["content_sha256"],
            content_bytes=row["content_bytes"],
            strategy_name=row["strategy_name"],
            strategy_version=row["strategy_version"],
            strategy_sha256=row["strategy_sha256"],
            domain_fingerprint=domain_fingerprint(row["domain_id"] or None),
            stats=batch_stats(RunStats(**json.loads(row["stats_json"]))),
            output_path=output_path,
        )
    )


def publish_stream_receipt(
    db: "Database", master: MasterKey, job_id: str, *, output_path: Path
) -> bool:
    """流式作业：成功发布结果后生成凭证；已存在则跳过（幂等补发）。

    统计计数取自最后一个安全检查点（调用方保证最终检查点已提交）。
    """
    path = receipt_path_for_output(output_path)
    if path.exists():
        return True
    job = db.get_stream_job(job_id)
    if job is None or not output_path.exists():
        return False
    sha, size = sha256_file(output_path)
    receipt = build_receipt(
        master,
        job_id=job_id,
        job_kind=KIND_STREAM,
        input_sha256=job.content_sha256,
        input_bytes=job.bytes_total,
        strategy_name=job.strategy_name,
        strategy_version=job.strategy_version,
        strategy_sha256=job.strategy_sha256,
        domain_fingerprint=job.domain_fingerprint,
        stats={
            "records": job.records_processed,
            "fields_scanned": job.fields_scanned,
            "audit_entries": job.audit_count,
            "risk_findings": job.risk_count,
            "by_action": job.by_action,
            "by_rule": job.by_rule,
        },
        output_filename=output_path.name,
        output_format="ndjson",
        output_sha256=sha,
        output_bytes=size,
    )
    write_receipt(path, receipt)
    return True


def publish_bundle_receipt(
    db: "Database", master: MasterKey, job_id: str, *, output_path: Path
) -> bool:
    """诊断包作业：成功发布结果 ZIP 后生成凭证（另列 ZIP 内各文件摘要）。"""
    path = receipt_path_for_output(output_path)
    if path.exists():
        return True
    job = db.get_bundle_job(job_id)
    if job is None or not output_path.exists():
        return False
    sha, size = sha256_file(output_path)
    entries = zip_entry_digests(output_path)
    files = db.bundle_files_for_manifest(job_id)
    receipt = build_receipt(
        master,
        job_id=job_id,
        job_kind=KIND_BUNDLE,
        input_sha256=job.content_sha256,
        input_bytes=job.bytes_total,
        strategy_name=job.strategy_name,
        strategy_version=job.strategy_version,
        strategy_sha256=job.strategy_sha256,
        domain_fingerprint=job.domain_fingerprint,
        stats={
            "records": job.records_processed,
            "fields_scanned": job.fields_scanned,
            "audit_entries": job.audit_count,
            "risk_findings": job.risk_count,
            "files_total": job.files_total,
            "files_redacted": sum(1 for f in files if f.status == "redacted"),
            "files_skipped": sum(1 for f in files if f.status == "skipped"),
            "files_failed": sum(1 for f in files if f.status == "failed"),
            "by_action": job.by_action,
            "by_rule": job.by_rule,
        },
        output_filename=output_path.name,
        output_format="zip",
        output_sha256=sha,
        output_bytes=size,
        files=entries,
    )
    write_receipt(path, receipt)
    return True


# ---------- 校验 ----------


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


_BASE_KEYS = {
    "format", "receipt_id", "job_id", "job_kind", "created_at",
    "key_fingerprint", "domain_fingerprint", "input", "strategy",
    "stats", "output", "tag",
}


def _structure_ok(receipt: dict[str, Any], job_kind: str) -> bool:
    """正版凭证必满足的结构与字段类型约束（不满足即视为被改动/损坏）。"""
    expected_keys = _BASE_KEYS | ({"files"} if job_kind == KIND_BUNDLE else set())
    if set(receipt.keys()) != expected_keys:
        return False
    if not all(
        isinstance(receipt[k], str)
        for k in ("receipt_id", "job_id", "job_kind", "created_at",
                  "key_fingerprint", "domain_fingerprint")
    ):
        return False
    if not _is_hex64(receipt["tag"]):
        return False
    input_section = receipt["input"]
    if not isinstance(input_section, dict):
        return False
    if not set(input_section.keys()) <= {"sha256", "bytes"}:
        return False
    if not _is_hex64(input_section.get("sha256")):
        return False
    if "bytes" in input_section and not _is_nonnegative_int(input_section["bytes"]):
        return False
    strategy = receipt["strategy"]
    if not isinstance(strategy, dict) or set(strategy.keys()) != {
        "name", "version", "sha256",
    }:
        return False
    if not isinstance(strategy["name"], str):
        return False
    if not isinstance(strategy["version"], str):
        return False
    if not _is_hex64(strategy["sha256"]):
        return False
    if not isinstance(receipt["stats"], dict):
        return False
    output = receipt["output"]
    if not isinstance(output, dict) or set(output.keys()) != {
        "filename", "format", "sha256", "bytes",
    }:
        return False
    if not isinstance(output["filename"], str):
        return False
    if not isinstance(output["format"], str):
        return False
    if not _is_hex64(output["sha256"]) or not _is_nonnegative_int(output["bytes"]):
        return False
    if job_kind == KIND_BUNDLE:
        files = receipt["files"]
        if not isinstance(files, list):
            return False
        for entry in files:
            if not isinstance(entry, dict) or set(entry.keys()) != {
                "path", "sha256", "bytes",
            }:
                return False
            if not isinstance(entry["path"], str):
                return False
            if not _is_hex64(entry["sha256"]):
                return False
            if not _is_nonnegative_int(entry["bytes"]):
                return False
    return True


def verify_receipt(
    master: MasterKey,
    receipt: dict[str, Any],
    *,
    job_id: str,
    job_kind: str,
    output_path: Path,
) -> dict[str, Any]:
    """校验凭证：重算标签与现有结果摘要，不重新脱敏、不返回文件内容。

    按 格式版本 → 作业绑定 → 结构 → 密钥指纹 → 标签 → 结果存在 → 内容摘要
    的顺序判定，任一阶段失败即给出对应 verdict，后续阶段记为 skipped。
    """
    checks = {stage: "skipped" for stage in _STAGES}

    def _done(verdict: str, detail: str, *, ok: bool = False) -> dict[str, Any]:
        return {
            "job_id": job_id,
            "job_kind": job_kind,
            "ok": ok,
            "verdict": verdict,
            "detail": detail,
            "checks": checks,
        }

    # 1) 格式版本：不支持的版本无法解释，直接判定
    if receipt.get("format") != RECEIPT_FORMAT:
        checks["format"] = "failed"
        return _done(
            VERDICT_UNSUPPORTED_FORMAT,
            f"不支持的凭证格式版本（本服务支持 {RECEIPT_FORMAT}）",
        )
    checks["format"] = "ok"

    # 2) 作业绑定：凭证必须属于本入口的该作业（job_id 与作业类型均一致）
    if receipt.get("job_id") != job_id or receipt.get("job_kind") != job_kind:
        checks["binding"] = "failed"
        return _done(VERDICT_JOB_MISMATCH, "凭证与本作业不对应（job_id 或作业类型不符）")
    checks["binding"] = "ok"

    # 3) 结构完整性：正版凭证必满足的字段与类型约束
    if not _structure_ok(receipt, job_kind):
        checks["structure"] = "failed"
        return _done(VERDICT_RECEIPT_TAMPERED, "凭证结构不完整或字段类型不符，疑似被改动")
    checks["structure"] = "ok"

    # 4) 密钥指纹：不一致说明签发密钥与当前主密钥不同（如密钥已轮换）
    if receipt["key_fingerprint"] != key_fingerprint(master):
        checks["key"] = "failed"
        return _done(VERDICT_KEY_MISMATCH, "凭证签发密钥与当前主密钥不匹配")
    checks["key"] = "ok"

    # 5) 标签：用凭证子密钥重算 HMAC-SHA256 并常量时间比较
    if not hmac.compare_digest(compute_tag(master, receipt), receipt["tag"]):
        checks["tag"] = "failed"
        return _done(VERDICT_RECEIPT_TAMPERED, "凭证标签校验失败，内容已被改动")
    checks["tag"] = "ok"

    # 6) 结果文件必须仍在（已清理的结果无法核对内容）
    if not output_path.is_file():
        checks["result"] = "failed"
        return _done(VERDICT_RESULT_MISSING, "已发布的结果文件不存在（可能已被清理）")
    checks["result"] = "ok"

    # 7) 结果内容摘要：诊断包同时逐文件核对 ZIP 内条目
    actual_sha, actual_bytes = sha256_file(output_path)
    output = receipt["output"]
    if output["sha256"] != actual_sha or output["bytes"] != actual_bytes:
        checks["content"] = "failed"
        return _done(VERDICT_CONTENT_MISMATCH, "结果文件摘要与凭证记录不符")
    if job_kind == KIND_BUNDLE:
        try:
            entries = zip_entry_digests(output_path)
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            checks["content"] = "failed"
            return _done(VERDICT_CONTENT_MISMATCH, "结果 ZIP 无法读取，内容与凭证不符")
        if entries != receipt["files"]:
            checks["content"] = "failed"
            return _done(VERDICT_CONTENT_MISMATCH, "结果 ZIP 内文件摘要与凭证记录不符")
    checks["content"] = "ok"
    return _done(VERDICT_OK, "凭证标签与结果摘要均一致", ok=True)
