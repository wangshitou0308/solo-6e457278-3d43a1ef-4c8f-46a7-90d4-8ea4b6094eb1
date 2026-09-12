"""本地数据保留与安全清理：保留策略、保留锁、预览与可恢复的清理执行。

设计要点
--------
* **统一管理三类作业**：小批量（``batch``，jobs/ 目录）、流式 NDJSON
  （``stream``，streams/ 目录）与诊断包（``bundle``，bundles/ 目录）。
  保留期限可按 **作业类型 × 终态 × 是否需复核** 配置；内置默认规则首次启动
  播种到 ``retention_rules`` 表，调用方可覆盖（含 ``null``=永久保留）或删除
  自定义覆盖后回退内置值。
* **保留锁**：可为指定作业设置带原因与到期时间的锁；到期前该作业不得删除。
  同一作业至多一把未释放锁；到期后自动失效（可重新加锁）。
* **预览不读内容**：预览只枚举**终态**作业的文件元数据（类别/相对路径/大小），
  绝不打开日志/结果文件，更不返回任何日志或审计内容。运行中（queued/running）
  作业、保留锁未到期、期限未满与永久保留规则的作业一律排除。
* **目标指纹**：对「待删作业三元组 + 文件(类别,路径,大小)」规范化哈希。执行
  必须回传预览摘要；执行时重新计算的目标与预览不一致（目标发生变化）即拒绝
  （409），要求重新预览。
* **计划先持久化**：执行先把计划头与逐作业项落库（pending），worker 再逐项
  删除；服务重启后 pending/running 计划自动继续。
* **限定数据目录内删除**：所有路径由服务端按 job_id 构造，删除前再做
  realpath 越界校验与符号链接拒绝；文件缺失视为已删（幂等），符号链接/越界
  路径不跟随、只记录，其他部分失败逐项记录且可重试。
* **文件先删、记录随后**：单个作业的文件全部安全删除后，才在同一删除批次里
  删除其数据库记录（审计/风险/作业行/保留锁）；任何文件项失败则保留记录，
  供重试继续。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import config
from . import bundle_jobs, stream_jobs
from .database import Database, utcnow_iso
from .models import (
    CleanupPlanModel,
    PlanItemModel,
    PreviewFileEntry,
    PreviewItem,
    RetentionAuditEntry,
    RetentionLockModel,
    RetentionRuleModel,
)

# (job_kind, terminal_status, needs_review 键, 保留天数；None=永久保留)
# 需复核结果默认显著多保留，便于人工确认后再清理。
DEFAULT_RETENTION_RULES: list[tuple[str, str, str, float | None]] = [
    ("batch", "succeeded", "false", 30),
    ("batch", "succeeded", "true", 90),
    ("stream", "succeeded", "false", 14),
    ("stream", "succeeded", "true", 90),
    ("stream", "failed", "any", 7),
    ("stream", "cancelled", "any", 3),
    ("bundle", "succeeded", "false", 14),
    ("bundle", "succeeded", "true", 90),
    ("bundle", "failed", "any", 7),
    ("bundle", "cancelled", "any", 3),
]

JOB_KINDS = ("batch", "stream", "bundle")
TERMINAL_STATUSES = ("succeeded", "failed", "cancelled")
RUNNING_STATUSES = ("queued", "running")

# 清理计划在进程内串行执行（删除本就不应并发）
_cleanup_run_lock = threading.Lock()


# ---------- 时间 ----------


def _now(now: datetime | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def parse_iso(value: str | None) -> datetime | None:
    """解析数据库内 ISO 时间戳为感知 UTC datetime；失败返回 None。"""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    return _now(dt).isoformat(timespec="seconds")


def _expires_key(dt: datetime) -> str:
    """到期时间的比较键：统一到秒精度 UTC（入库按秒存储）。"""
    return to_iso(dt)


# ---------- 策略规则 ----------


def _rule_row_to_model(row: sqlite3.Row) -> RetentionRuleModel:
    return RetentionRuleModel(
        job_kind=row["job_kind"],
        terminal_status=row["terminal_status"],
        needs_review=row["needs_review"],
        retention_days=row["retention_days"],
        builtin=bool(row["builtin"]),
        updated_at=row["updated_at"],
    )


def get_policy(db: Database) -> list[RetentionRuleModel]:
    return [_rule_row_to_model(r) for r in db.list_retention_rules()]


def resolve_rule(
    db: Database, *, job_kind: str, terminal_status: str, needs_review: bool
) -> sqlite3.Row | None:
    """解析生效规则。

    候选为精确复核位键（true/false）与 ``any`` 兜底键：

    * 自定义覆盖优先于内置默认（自定义 ``any`` 的永久保留可压住内置精确键）；
    * 同为内置或同为自定义时，精确键优先于 ``any`` 兜底。
    """
    review_key = "true" if needs_review else "false"
    exact = db.get_retention_rule(
        job_kind=job_kind, terminal_status=terminal_status, needs_review=review_key
    )
    fallback = db.get_retention_rule(
        job_kind=job_kind, terminal_status=terminal_status, needs_review="any"
    )
    # 自定义覆盖优先于内置；同来源时精确复核位键优先于 any 兜底
    priority = {(False, True): 0, (False, False): 1, (True, True): 2, (True, False): 3}
    candidates = [r for r in (exact, fallback) if r is not None]
    if not candidates:
        return None
    return min(candidates, key=lambda r: priority[(bool(r["builtin"]), r["needs_review"] == "any")])


# ---------- 保留锁 ----------


def _lock_state(row: sqlite3.Row, now: datetime) -> str:
    """active=未释放且未到期；expired=已到期（含到期后由系统标记释放）；released=提前释放。"""
    expires = parse_iso(row["expires_at"])
    if row["released_at"]:
        return "expired" if (expires is not None and expires <= now) else "released"
    return "active" if (expires is not None and expires > now) else "expired"


def lock_row_to_model(row: sqlite3.Row, now: datetime | None = None) -> RetentionLockModel:
    current = _now(now)
    return RetentionLockModel(
        job_kind=row["job_kind"],
        job_id=row["job_id"],
        reason=row["reason"],
        expires_at=parse_iso(row["expires_at"]) or current,
        created_at=row["created_at"],
        state=_lock_state(row, current),
    )


def active_lock(
    db: Database, job_kind: str, job_id: str, now: datetime
) -> sqlite3.Row | None:
    """返回仍在有效期内的未释放锁；未释放但已到期的锁先标记失效。"""
    row = db.active_retention_lock(job_kind, job_id)
    if row is None:
        return None
    expires = parse_iso(row["expires_at"])
    if expires is not None and expires > now:
        return row
    db.expire_retention_lock(row["id"])
    return None


def job_exists(db: Database, job_kind: str, job_id: str) -> bool:
    if job_kind == "batch":
        return db.get_job(job_id) is not None
    if job_kind == "stream":
        return db.get_stream_job(job_id) is not None
    return db.get_bundle_job(job_id) is not None


def create_lock(
    db: Database, *, job_kind: str, job_id: str, reason: str,
    expires_at: datetime, now: datetime | None = None,
) -> RetentionLockModel:
    """加锁；既有未释放锁未到期返回 None（冲突），已到期则失效后续建。"""
    current = _now(now)
    expires = _now(expires_at)
    if expires <= current:
        raise ValueError("expires_at 必须晚于当前时间")
    existing = db.active_retention_lock(job_kind, job_id)
    if existing is not None:
        exp = parse_iso(existing["expires_at"])
        if exp is not None and exp > current:
            raise LockConflictError(_lock_row_identity(existing))
        db.expire_retention_lock(existing["id"])
    row = db.create_retention_lock(
        job_kind=job_kind, job_id=job_id, reason=reason,
        expires_at=to_iso(expires),
    )
    db.add_retention_audit(
        "lock.created", job_kind=job_kind, job_id=job_id,
        detail={"reason": reason, "expires_at": to_iso(expires)},
    )
    return lock_row_to_model(row, current)


class LockConflictError(Exception):
    def __init__(self, identity: dict[str, Any]) -> None:
        super().__init__("该作业已有生效中的保留锁")
        self.identity = identity


def _lock_row_identity(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "job_kind": row["job_kind"], "job_id": row["job_id"],
        "expires_at": row["expires_at"], "reason": row["reason"],
    }


# ---------- 文件布局（限定数据目录内、由 job_id 派生） ----------


def _receipt(path: Path) -> Path:
    from .receipts import receipt_path_for_output

    return receipt_path_for_output(path)


def _job_files(job_kind: str, job_id: str) -> list[tuple[str, Path]]:
    """该作业类型所有可能由本服务产生的文件/目录（终态后）。

    每项 (category, path)：结果、凭证、（残留的）原始输入、半成品输出、
    诊断包暂存目录。路径全部由服务端按 job_id 构造，调用方无法注入路径。
    """
    if job_kind == "batch":
        jobs_dir = config.settings.data_dir / "jobs"
        # batch 的扩展名由数据库记录决定；两个候选都枚举，存在才计入
        return [
            ("result", jobs_dir / f"{job_id}.json"),
            ("result", jobs_dir / f"{job_id}.ndjson"),
            ("receipt", _receipt(jobs_dir / f"{job_id}.json")),
            ("receipt", _receipt(jobs_dir / f"{job_id}.ndjson")),
        ]
    if job_kind == "stream":
        return [
            ("result", stream_jobs.final_output_path(job_id)),
            ("receipt", _receipt(stream_jobs.final_output_path(job_id))),
            ("raw_input", stream_jobs.raw_path(job_id)),
            ("partial_output", stream_jobs.partial_output_path(job_id)),
        ]
    return [
        ("result", bundle_jobs.final_output_path(job_id)),
        ("receipt", _receipt(bundle_jobs.final_output_path(job_id))),
        ("raw_input", bundle_jobs.raw_path(job_id)),
        ("bundle_staging", bundle_jobs.staging_dir(job_id)),
    ]


def _allowed_roots() -> list[Path]:
    data = config.settings.data_dir.resolve()
    return [
        data / "jobs",
        (config.settings.data_dir / "streams").resolve(),
        (config.settings.data_dir / "bundles").resolve(),
    ]


def _is_within_roots(path: Path, roots: Iterable[Path]) -> bool:
    try:
        target = Path(os.path.realpath(str(path)))
    except OSError:
        return False
    for root in roots:
        if target == root or target.is_relative_to(root):
            return True
    return False


def _existing_file_entries(
    job_kind: str, job_id: str
) -> list[PreviewFileEntry]:
    """枚举现存文件（只 stat，不打开内容）；符号链接标记但不跟随。"""
    roots = _allowed_roots()
    entries: list[PreviewFileEntry] = []
    seen: set[str] = set()
    for category, path in _job_files(job_kind, job_id):
        if not path.exists() and not path.is_symlink():
            continue
        rel = _rel(path)
        if rel in seen:  # batch 的 json/ndjson 候选会产生同一凭证路径，去重
            continue
        seen.add(rel)
        if category == "bundle_staging" and path.is_dir() and not path.is_symlink():
            # 暂存目录：汇总其中普通文件大小（按类别统计，路径只到目录）
            total = 0
            symlink = False
            refused = False
            for child in path.rglob("*"):
                if child.is_symlink():
                    symlink = True
                    continue
                if not _is_within_roots(child, roots):
                    refused = True
                    continue
                if child.is_file():
                    try:
                        total += child.stat().st_size
                    except OSError:
                        pass
            note = None
            if refused:
                note = "contains_out_of_tree_path"
            elif symlink:
                note = "contains_symlink"
            entries.append(PreviewFileEntry(
                category=category, path=rel + "/", bytes=total, note=note,
            ))
            continue
        if path.is_symlink():
            # 预览不跟随符号链接：大小记 0，执行时拒绝并记录
            entries.append(PreviewFileEntry(
                category=category, path=rel, bytes=0, note="symlink",
            ))
            continue
        if not _is_within_roots(path, roots):
            entries.append(PreviewFileEntry(
                category=category, path=rel, bytes=0, note="out_of_tree",
            ))
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        entries.append(PreviewFileEntry(category=category, path=rel, bytes=size))
    return entries


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(config.settings.data_dir.resolve()))
    except (OSError, ValueError):
        return path.name


# ---------- 预览 ----------


def _terminal_jobs(
    db: Database, job_kinds: tuple[str, ...]
) -> list[tuple[str, str, str, bool, datetime]]:
    """枚举终态作业：(kind, id, status, needs_review, 终态时间)。"""
    out: list[tuple[str, str, str, bool, datetime]] = []
    if "batch" in job_kinds:
        with db._conn() as conn:  # noqa: SLF001 - 同包只读查询
            rows = conn.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
        for r in rows:
            completed = parse_iso(r["created_at"])
            if completed is None:
                continue
            out.append(("batch", r["id"], "succeeded",
                        bool(r["needs_review"]), completed))
    if "stream" in job_kinds:
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM stream_jobs WHERE status NOT IN ('queued','running') "
                "ORDER BY rowid"
            ).fetchall()
        for r in rows:
            completed = parse_iso(r["updated_at"]) or parse_iso(r["created_at"])
            if completed is None:
                continue
            out.append(("stream", r["id"], r["status"],
                        bool(r["risk_count"] and r["risk_count"] > 0), completed))
    if "bundle" in job_kinds:
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM bundle_jobs WHERE status NOT IN ('queued','running') "
                "ORDER BY rowid"
            ).fetchall()
        for r in rows:
            completed = parse_iso(r["updated_at"]) or parse_iso(r["created_at"])
            if completed is None:
                continue
            out.append(("bundle", r["id"], r["status"],
                        bool(r["risk_count"] and r["risk_count"] > 0), completed))
    return out


def build_preview(
    db: Database, *, job_kinds: tuple[str, ...] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """计算清理预览：只读取作业元数据与文件 stat，不读取任何文件内容。"""
    current = _now(now)
    kinds = job_kinds or JOB_KINDS
    blocked = {"locked": 0, "retained": 0, "running": 0, "permanent": 0}
    items: list[PreviewItem] = []

    # 运行中作业计数（仅针对被扫描类型）
    if "stream" in kinds:
        with db._conn() as conn:
            blocked["running"] += conn.execute(
                "SELECT COUNT(*) AS c FROM stream_jobs "
                "WHERE status IN ('queued','running')"
            ).fetchone()["c"]
    if "bundle" in kinds:
        with db._conn() as conn:
            blocked["running"] += conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_jobs "
                "WHERE status IN ('queued','running')"
            ).fetchone()["c"]

    for job_kind, job_id, status, needs_review, completed in _terminal_jobs(db, kinds):
        if active_lock(db, job_kind, job_id, current) is not None:
            blocked["locked"] += 1
            continue
        rule = resolve_rule(
            db, job_kind=job_kind, terminal_status=status, needs_review=needs_review
        )
        if rule is None or rule["retention_days"] is None:
            blocked["permanent"] += 1
            continue
        deadline = completed + timedelta(days=float(rule["retention_days"]))
        if current < deadline:
            blocked["retained"] += 1
            continue
        files = _existing_file_entries(job_kind, job_id)
        items.append(PreviewItem(
            job_kind=job_kind,
            job_id=job_id,
            terminal_status=status,
            needs_review=needs_review,
            completed_at=completed.isoformat(timespec="seconds"),
            retention_days=float(rule["retention_days"]),
            rule_source="builtin" if rule["builtin"] else "custom",
            expired=True,
            files=files,
            bytes_total=sum(f.bytes for f in files),
        ))

    items.sort(key=lambda i: (i.job_kind, i.completed_at, i.job_id))
    by_category: dict[str, int] = {}
    file_count = 0
    for item in items:
        for f in item.files:
            by_category[f.category] = by_category.get(f.category, 0) + f.bytes
            file_count += 1
    fingerprint = compute_fingerprint(items)
    return {
        "preview_id": fingerprint,
        "generated_at": to_iso(current),
        "target_fingerprint": fingerprint,
        "job_kinds": list(kinds),
        "items": items,
        "job_count": len(items),
        "file_count": file_count,
        "bytes_total": sum(i.bytes_total for i in items),
        "by_category": dict(sorted(by_category.items())),
        "blocked": blocked,
    }


def _canonical_files(item: PreviewItem) -> list[list[Any]]:
    return [[f.category, f.path, f.bytes] for f in sorted(item.files, key=lambda f: f.path)]


def compute_fingerprint(items: list[PreviewItem]) -> str:
    """目标指纹：作业三元组 + 文件(类别,路径,大小) 的规范化 SHA-256（不读内容）。"""
    payload = [
        [i.job_kind, i.job_id, i.terminal_status, str(i.needs_review).lower(),
         i.completed_at, _canonical_files(i)]
        for i in items
    ]
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ---------- 安全删除 ----------


class UnsafePathError(Exception):
    """符号链接或越出限定数据目录的路径。"""


def _safe_remove(path: Path, *, roots: list[Path]) -> str:
    """删除单个普通文件；返回 outcome 标签。

    * ``deleted``：已删除；``missing``：原本就不存在（幂等）；
    * ``symlink_refused``：路径（含路径上任一级）是符号链接，拒绝跟随；
    * ``path_refused``：realpath 越出限定数据目录，拒绝删除。
    """
    if path.is_symlink():
        raise UnsafePathError("symlink")
    if not path.exists():
        return "missing"
    # 路径上任一级都不得是符号链接（realpath 与逐段 lstat 双重确认）
    if not _is_within_roots(path, roots):
        raise UnsafePathError("out_of_tree")
    os.unlink(path)
    return "deleted"


def _safe_rmtree(path: Path, *, roots: list[Path]) -> list[dict[str, Any]]:
    """安全删除诊断包暂存目录；逐文件检查，符号链接/越界只记录不跟随。"""
    outcomes: list[dict[str, Any]] = []
    if not path.exists() and not path.is_symlink():
        return outcomes
    if path.is_symlink():
        raise UnsafePathError("symlink")
    if not _is_within_roots(path, roots):
        raise UnsafePathError("out_of_tree")
    for child in sorted(path.rglob("*"), reverse=True):
        rel = _rel(child)
        if child.is_symlink() or not _is_within_roots(child, roots):
            outcomes.append({
                "category": "bundle_staging", "path": rel,
                "outcome": "symlink_refused" if child.is_symlink() else "path_refused",
                "bytes": 0, "error": "符号链接，拒绝删除"
                if child.is_symlink() else "越界路径，拒绝删除",
            })
            continue
        try:
            if child.is_file() or child.is_symlink():
                size = child.stat().st_size if not child.is_symlink() else 0
                if child.is_symlink():
                    outcomes.append({
                        "category": "bundle_staging", "path": rel,
                        "outcome": "symlink_refused", "bytes": 0,
                        "error": "符号链接，拒绝删除",
                    })
                    continue
                os.unlink(child)
                outcomes.append({
                    "category": "bundle_staging", "path": rel,
                    "outcome": "deleted", "bytes": size,
                })
            elif child.is_dir():
                # 仅在目录为空（安全文件已删、无符号链接残留）时删除
                try:
                    child.rmdir()
                except OSError:
                    pass
        except OSError as exc:
            outcomes.append({
                "category": "bundle_staging", "path": rel,
                "outcome": "failed", "bytes": 0, "error": str(exc),
            })
    # 根目录：无符号链接/越界残留时移除
    leftovers = [o for o in outcomes if o["outcome"] in
                 ("symlink_refused", "path_refused", "failed")]
    if not leftovers:
        shutil.rmtree(path, ignore_errors=True)
    return outcomes


# ---------- 清理 worker ----------


def _plan_model(db: Database, row: sqlite3.Row) -> CleanupPlanModel:
    item_rows = db.cleanup_plan_items(row["id"])
    items = [
        PlanItemModel(
            job_kind=r["job_kind"],
            job_id=r["job_id"],
            status=r["status"],
            planned_files=[
                PreviewFileEntry(**f) for f in json.loads(r["planned_files_json"] or "[]")
            ],
            processed=r["processed"],
            deleted_bytes=r["deleted_bytes"],
            outcomes=json.loads(r["outcomes_json"] or "[]"),
        )
        for r in item_rows
    ]
    return CleanupPlanModel(
        plan_id=row["id"],
        idempotency_key=row["idempotency_key"],
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        target_fingerprint=row["target_fingerprint"],
        submitted_preview=json.loads(row["submitted_preview_json"]),
        jobs_total=row["jobs_total"],
        jobs_done=row["jobs_done"],
        jobs_failed=row["jobs_failed"],
        files_processed=row["files_processed"],
        bytes_deleted=row["bytes_deleted"],
        error=row["error"],
        items=items,
    )


def get_plan(db: Database, plan_id: str) -> CleanupPlanModel | None:
    row = db.get_cleanup_plan_row(plan_id)
    return _plan_model(db, row) if row else None


def _guards_pass(
    db: Database, *, job_kind: str, job_id: str,
    planned_status: str, planned_review: bool, now: datetime,
) -> tuple[bool, str | None]:
    """执行前的逐作业复核（目标变化的最后一道防线）：

    * 作业必须仍存在、仍处于计划时的终态（运行中作业不得删除）；
    * 生效中的保留锁不得删除；
    * 按**当前**策略与终态/复核位重新解析期限，已不满足过期条件不得删除
      （复核期限未满的结果不得删除）。
    """
    if active_lock(db, job_kind, job_id, now) is not None:
        return False, "作业存在生效中的保留锁"
    row = db.get_any_job(job_kind, job_id)
    if row is None:
        return False, "作业已不存在"
    if job_kind == "batch":
        current_status = "succeeded"
        needs_review = bool(row["needs_review"])
        completed = parse_iso(row["created_at"])
    else:
        current_status = row["status"]
        needs_review = bool(row["risk_count"] and row["risk_count"] > 0)
        completed = parse_iso(row["updated_at"]) or parse_iso(row["created_at"])
    if current_status in RUNNING_STATUSES:
        return False, "作业仍在运行"
    if current_status != planned_status or needs_review != planned_review:
        return False, "作业终态或复核状态与预览时不同"
    rule = resolve_rule(
        db, job_kind=job_kind, terminal_status=current_status,
        needs_review=needs_review,
    )
    if rule is None or rule["retention_days"] is None:
        return False, "保留策略已变为永久保留"
    if completed is not None:
        deadline = completed + timedelta(days=float(rule["retention_days"]))
        if now < deadline:
            return False, "保留期限尚未届满"
    return True, None


def _delete_item(
    db: Database, item_row: sqlite3.Row, *, now: datetime
) -> tuple[str, list[dict[str, Any]], int, int]:
    """删除单个作业项；返回 (status, outcomes, processed_count, deleted_bytes)。

    status=done 时文件与数据库记录均已处理；failed 时记录原样保留供重试。
    """
    job_kind = item_row["job_kind"]
    job_id = item_row["job_id"]
    planned = json.loads(item_row["planned_files_json"] or "[]")

    ok, reason = _guards_pass(
        db, job_kind=job_kind, job_id=job_id,
        planned_status=item_row["terminal_status"],
        planned_review=bool(item_row["needs_review"]), now=now,
    )
    if not ok:
        return "failed", [{
            "category": "guard", "path": None, "outcome": "guard_refused",
            "bytes": 0, "error": reason,
        }], 0, 0

    roots = _allowed_roots()
    outcomes: list[dict[str, Any]] = []
    deleted_bytes = 0
    processed = 0
    failed = False

    for entry in planned:
        category = entry["category"]
        rel = entry["path"]
        processed += 1
        path = config.settings.data_dir / rel.rstrip("/")

        if category == "bundle_staging":
            if not path.exists() and not path.is_symlink():
                outcomes.append({
                    "category": category, "path": rel,
                    "outcome": "missing", "bytes": 0,
                })
                continue
            try:
                sub = _safe_rmtree(path, roots=roots)
            except UnsafePathError as exc:
                failed = True
                outcomes.append({
                    "category": category, "path": rel,
                    "outcome": "symlink_refused" if str(exc) == "symlink"
                    else "path_refused", "bytes": 0,
                    "error": "符号链接，拒绝删除" if str(exc) == "symlink"
                    else "越界路径，拒绝删除",
                })
                continue
            if not sub:
                outcomes.append({
                    "category": category, "path": rel,
                    "outcome": "deleted", "bytes": 0,
                })
            else:
                outcomes.extend(sub)
                deleted_bytes += sum(
                    o.get("bytes", 0) for o in sub if o["outcome"] == "deleted"
                )
                if any(o["outcome"] in ("symlink_refused", "path_refused", "failed")
                       for o in sub):
                    failed = True
            continue

        try:
            size = path.stat().st_size if path.exists() and not path.is_symlink() else 0
            outcome = _safe_remove(path, roots=roots)
        except UnsafePathError as exc:
            failed = True
            outcomes.append({
                "category": category, "path": rel,
                "outcome": "symlink_refused" if str(exc) == "symlink"
                else "path_refused", "bytes": 0,
                "error": "符号链接，拒绝删除" if str(exc) == "symlink"
                else "越界路径，拒绝删除",
            })
            continue
        except OSError as exc:
            failed = True
            outcomes.append({
                "category": category, "path": rel, "outcome": "failed",
                "bytes": 0, "error": str(exc),
            })
            continue
        if outcome == "deleted":
            deleted_bytes += size
        outcomes.append({
            "category": category, "path": rel, "outcome": outcome,
            "bytes": size if outcome == "deleted" else 0,
        })

    if failed:
        return "failed", outcomes, processed, deleted_bytes
    # 文件全部安全删除后才删除数据库记录
    db.delete_job_records(job_kind, job_id)
    return "done", outcomes, processed, deleted_bytes


def run_cleanup_plan(
    plan_id: str, get_db: Callable[[], Database],
    *, retry_failed_only: bool = False,
    now: datetime | None = None,
) -> CleanupPlanModel:
    """执行（或继续/重试）一个已持久化的清理计划。进程内串行。

    首次执行沿用提交预览时的评估时刻（持久化在计划摘要里），保证“目标未变化”
    的判定在异步执行/重启后仍可复现；重试则按当前时刻重新复核安全守卫。
    """
    with _cleanup_run_lock:
        db = get_db()
        row = db.get_cleanup_plan_row(plan_id)
        if row is None:
            raise KeyError(plan_id)
        if row["status"] == "succeeded":
            return _plan_model(db, row)
        # 首轮执行使用提交时的评估时刻；重试/重启续跑用当前时刻重新复核
        if now is None:
            submitted = json.loads(row["submitted_preview_json"] or "{}")
            if retry_failed_only or row["started_at"]:
                current = _now()
            else:
                current = parse_iso(submitted.get("evaluated_now")) or _now()
        else:
            current = _now(now)
        db.mark_cleanup_plan_running(plan_id)
        db.add_retention_audit(
            "cleanup.plan.retried" if retry_failed_only else "cleanup.plan.started",
            plan_id=plan_id,
        )

        files_processed = 0
        bytes_deleted = 0
        for item_row in db.cleanup_plan_items(plan_id):
            if item_row["status"] == "done":
                files_processed += item_row["processed"]
                bytes_deleted += item_row["deleted_bytes"]
                continue
            # 普通执行/重启续跑：处理 pending 与 failed；显式重试：只处理 failed
            if retry_failed_only and item_row["status"] != "failed":
                continue
            status, outcomes, processed, item_bytes = _delete_item(
                db, item_row, now=current
            )
            db.mark_plan_item(
                item_row["id"], status=status, processed=processed,
                deleted_bytes=item_bytes, outcomes=outcomes,
            )
            db.add_retention_audit(
                f"cleanup.item.{status}",
                job_kind=item_row["job_kind"], job_id=item_row["job_id"],
                plan_id=plan_id,
                detail={"outcomes": outcomes, "bytes_deleted": item_bytes},
            )

        # 以最终逐项状态汇总进度（含历史轮次的结果）
        all_rows = db.cleanup_plan_items(plan_id)
        jobs_done = sum(1 for r in all_rows if r["status"] == "done")
        jobs_failed = sum(1 for r in all_rows if r["status"] == "failed")
        jobs_pending = sum(1 for r in all_rows if r["status"] == "pending")
        files_processed = sum(r["processed"] for r in all_rows)
        bytes_deleted = sum(r["deleted_bytes"] for r in all_rows)
        db.update_cleanup_progress(
            plan_id, jobs_done=jobs_done, jobs_failed=jobs_failed,
            files_processed=files_processed, bytes_deleted=bytes_deleted,
        )

        if jobs_failed == 0 and jobs_pending == 0:
            final_status = "succeeded"
            error = None
        elif jobs_pending == 0:
            final_status = "partial"
            error = "部分作业文件删除失败，可调用重试接口继续"
        else:
            # 显式重试只处理失败项时，pending 项原封不动：计划仍可继续执行
            final_status = "partial" if retry_failed_only else "failed"
            error = ("失败项已尝试重试，仍有未处理作业项"
                     if retry_failed_only else "清理计划未完成，可重试")
        db.mark_cleanup_plan_finished(
            plan_id, status=final_status, jobs_failed=jobs_failed,
            files_processed=files_processed, bytes_deleted=bytes_deleted, error=error,
        )
        db.add_retention_audit(
            "cleanup.plan.finished", plan_id=plan_id,
            detail={"status": final_status, "jobs_done": jobs_done,
                    "jobs_failed": jobs_failed, "bytes_deleted": bytes_deleted},
        )
        return get_plan(db, plan_id)  # type: ignore[return-value]


def persist_plan(
    db: Database, *, preview: dict[str, Any], idempotency_key: str | None
) -> tuple[str, bool]:
    """先持久化计划，再执行。返回 (plan_id, replayed)。

    幂等：同幂等键或同目标指纹的既有计划直接回放。
    """
    if idempotency_key:
        existing = db.get_cleanup_plan_by_idempotency(idempotency_key)
        if existing is not None:
            return existing["id"], True
    existing = db.find_cleanup_plan_by_fingerprint(preview["target_fingerprint"])
    if existing is not None:
        return existing["id"], True

    plan_id = uuid.uuid4().hex
    items_payload: list[tuple[str, str, str, str, bool]] = []
    for item in preview["items"]:
        files = [f.model_dump() for f in item.files]
        items_payload.append((
            item.job_kind, item.job_id,
            json.dumps(files, ensure_ascii=False),
            item.terminal_status, item.needs_review,
        ))
    submitted = {
        "preview_id": preview["preview_id"],
        "job_kinds": preview.get("job_kinds"),
        "job_count": preview["job_count"],
        "file_count": preview["file_count"],
        "bytes_total": preview["bytes_total"],
        "evaluated_now": preview["generated_at"],
    }
    db.create_cleanup_plan(
        plan_id=plan_id, idempotency_key=idempotency_key,
        target_fingerprint=preview["target_fingerprint"],
        submitted_preview=submitted, items=items_payload,
    )
    db.add_retention_audit(
        "cleanup.plan.created", plan_id=plan_id,
        detail={"target_fingerprint": preview["target_fingerprint"],
                "job_count": preview["job_count"],
                "file_count": preview["file_count"],
                "bytes_total": preview["bytes_total"]},
    )
    return plan_id, False


# ---------- 重启恢复 ----------


_recovery_lock = threading.Lock()
_recovery_done = False


def recover_cleanup_plans(get_db: Callable[[], Database]) -> None:
    """服务重启后继续未完成的清理计划（pending/running）。幂等，只执行一次。"""
    global _recovery_done
    with _recovery_lock:
        if _recovery_done:
            return
        _recovery_done = True

    db = get_db()
    for row in db.resumable_cleanup_plans():
        try:
            run_cleanup_plan(row["id"], get_db)
        except Exception:
            # 单个计划异常不影响其他计划恢复；计划保持可重试状态
            continue


def reset_recovery() -> None:
    """测试辅助：允许再次触发恢复扫描。"""
    global _recovery_done
    with _recovery_lock:
        _recovery_done = False


# ---------- 审计 ----------


def audit_rows_to_models(rows: list[sqlite3.Row]) -> list[RetentionAuditEntry]:
    return [
        RetentionAuditEntry(
            id=r["id"], ts=r["ts"], action=r["action"], job_kind=r["job_kind"],
            job_id=r["job_id"], plan_id=r["plan_id"],
            detail=json.loads(r["detail_json"] or "{}"),
        )
        for r in rows
    ]
