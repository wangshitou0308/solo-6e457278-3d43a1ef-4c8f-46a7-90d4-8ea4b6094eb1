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
import sqlite3
import stat
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import config
from . import bundle_jobs, stream_jobs
from .database import Database
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
# 每个计划的执行代次：重试/重启恢复时递增，陈旧 worker 线程发现代次落后即退出
_plan_generation: dict[str, int] = {}
_plan_threads: dict[str, threading.Thread] = {}
_threads_lock = threading.Lock()

# 评估时间 now 的允许偏差。未来时间会让“仍在保留期内”的作业被提前清理，
# 因此未来方向只允许秒级时钟偏差；过去方向只可能让保留更保守（少删），放宽到 5 分钟。
MAX_NOW_FUTURE_SKEW = timedelta(seconds=5)
MAX_NOW_PAST_SKEW = timedelta(minutes=5)


# ---------- 时间 ----------


def _now(now: datetime | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


class UnsafePathError(Exception):
    """符号链接或越出限定数据目录的路径（删除目标本身或其父路径异常）。"""


class InvalidNowError(ValueError):
    """显式传入的评估时间 now 不被接受（未来时间或距当前过远）。"""


def validate_now(now: datetime | None) -> datetime | None:
    """规范化显式评估时间并拒绝可提前清理的未来时间。

    * ``now`` 比服务当前时间快超过 :data:`MAX_NOW_FUTURE_SKEW`：拒绝（防止把
      保留期未满的作业纳入目标，杜绝“预览入选、执行守卫又拒绝”的不一致）；
    * 比当前时间慢超过 :data:`MAX_NOW_PAST_SKEW`：拒绝（明显的陈旧时间戳）；
    * 偏差内视为时钟偏差，规范化为 UTC 后采用。
    """
    if now is None:
        return None
    value = _now(now)
    current = _now()
    delta = value - current
    if delta > MAX_NOW_FUTURE_SKEW:
        raise InvalidNowError(
            f"评估时间 now 不得晚于服务当前时间 {int(MAX_NOW_FUTURE_SKEW.total_seconds())}"
            " 秒以上；保留期限只能按服务当前时间评估，禁止用未来时间提前清理"
        )
    if -delta > MAX_NOW_PAST_SKEW:
        raise InvalidNowError(
            "评估时间 now 早于服务当前时间超过 "
            f"{int(MAX_NOW_PAST_SKEW.total_seconds() // 60)} 分钟"
        )
    return value


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


def _lock_state(row: sqlite3.Row) -> str:
    """锁状态只依据落库列：未释放=active；提前释放=released；到期失效=expired。

    未释放但已到期的锁由 :func:`active_lock` 惰性标记后才出现在 expired 列表，
    与清理评估使用完全相同的判定，不存在“两套时间”。
    """
    keys = row.keys()
    reason = row["release_reason"] if "release_reason" in keys else ""
    if not row["released_at"]:
        return "active"
    return reason if reason in ("expired", "released") else "released"


def lock_row_to_model(row: sqlite3.Row, now: datetime | None = None) -> RetentionLockModel:
    current = _now(now)
    return RetentionLockModel(
        job_kind=row["job_kind"],
        job_id=row["job_id"],
        reason=row["reason"],
        expires_at=parse_iso(row["expires_at"]) or current,
        created_at=row["created_at"],
        state=_lock_state(row),
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


def _canonical_files(db: Database, job_kind: str, job_id: str
                     ) -> list[tuple[str, Path]]:
    """作业终态后**应当存在**的规范文件集合（缺失也要在结果中留痕）。

    * batch：按数据库记录的真实格式取 result + receipt；
    * stream/bundle：仅成功终态有 result + receipt；失败/取消终态正常生命周期里
      已无成品，规范集合为空，只枚举可能残留的临时文件。
    """
    if job_kind == "batch":
        row = db.get_job_receipt_source(job_id)
        if row is None:
            return []
        result = config.settings.data_dir / "jobs" / f"{job_id}.{row['format']}"
        return [("result", result), ("receipt", _receipt(result))]
    if job_kind == "stream":
        job = db.get_stream_job(job_id)
        if job is not None and job.status == "succeeded" and job.output_filename:
            result = stream_jobs.final_output_path(job_id)
            return [("result", result), ("receipt", _receipt(result))]
        return []
    job = db.get_bundle_job(job_id)
    if job is not None and job.status == "succeeded" and job.output_filename:
        result = bundle_jobs.final_output_path(job_id)
        return [("result", result), ("receipt", _receipt(result))]
    return []


def _residual_files(job_kind: str, job_id: str) -> list[tuple[str, Path]]:
    """生命周期结束后**不应残留**、但若出现也要随作业清理的临时文件/目录。"""
    if job_kind == "batch":
        return []
    if job_kind == "stream":
        return [
            ("raw_input", stream_jobs.raw_path(job_id)),
            ("partial_output", stream_jobs.partial_output_path(job_id)),
        ]
    return [
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


def _lexical_within(path: Path, root: Path) -> bool:
    """不解析任何符号链接的词法包含判断（os.path.realpath 会把链接当成目标，
    从而让“链接指向界内目标”绕过检查，这里绝不能用它）。"""
    try:
        return path == root or path.is_relative_to(root)
    except OSError:
        return False


def _is_within_roots(path: Path, roots: Iterable[Path]) -> bool:
    """词法路径是否落在限定目录内；调用方须先用 ``is_symlink`` 拦截链接。"""
    lexical = Path(os.path.abspath(str(path)))
    return any(_lexical_within(lexical, r) for r in roots)


def _resolved_within_roots(path: Path, roots: Iterable[Path]) -> bool:
    """删除后对账用：realpath 解析后仍须在界内（防御父目录被替换为链接）。"""
    try:
        target = Path(os.path.realpath(str(path)))
    except OSError:
        return False
    return any(target == r or target.is_relative_to(r) for r in roots)


def _entries_for_path(category: str, path: Path, roots: list[Path],
                      *, canonical: bool) -> list[PreviewFileEntry]:
    """把单个规范文件/残留文件或暂存目录转换为预览条目（只 stat，不读内容）。"""
    rel = _rel(path)
    if category == "bundle_staging":
        return _staging_entries(path, roots)
    # 符号链接：预览不跟随，显式标注（执行时快速失败并记录）
    if path.is_symlink():
        return [PreviewFileEntry(category=category, path=rel, bytes=0,
                                 status="present", note="symlink")]
    if not path.exists():
        # 规范集合中的文件缺失也要留痕；残留临时文件缺失则忽略（正常状态）
        if canonical:
            return [PreviewFileEntry(category=category, path=rel, bytes=0,
                                     status="missing")]
        return []
    if not _is_within_roots(path, roots):
        return [PreviewFileEntry(category=category, path=rel, bytes=0,
                                 status="present", note="out_of_tree")]
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return [PreviewFileEntry(category=category, path=rel, bytes=size,
                             status="present")]


def _staging_entries(path: Path, roots: list[Path]) -> list[PreviewFileEntry]:
    """诊断包暂存目录：根条目始终存在；内含符号链接/越界路径时标注。"""
    rel = _rel(path) + "/"
    if path.is_symlink():
        return [PreviewFileEntry(category="bundle_staging", path=rel, bytes=0,
                                 status="present", note="symlink")]
    if not path.exists():
        return []  # 暂存目录是残留项，缺失属正常，不产生 missing 噪声
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
    note = ("contains_out_of_tree_path" if refused
            else "contains_symlink" if symlink else None)
    return [PreviewFileEntry(category="bundle_staging", path=rel, bytes=total,
                             status="present", note=note)]


def _existing_file_entries(
    db: Database, job_kind: str, job_id: str
) -> list[PreviewFileEntry]:
    """枚举待删文件：规范集合（缺失也记录）+ 现存残留临时文件。绝不读取内容。"""
    roots = _allowed_roots()
    entries: list[PreviewFileEntry] = []
    seen: set[str] = set()

    def _add(category: str, path: Path, *, canonical: bool) -> None:
        for entry in _entries_for_path(category, path, roots, canonical=canonical):
            if entry.path in seen:
                continue
            seen.add(entry.path)
            entries.append(entry)

    for category, path in _canonical_files(db, job_kind, job_id):
        _add(category, path, canonical=True)
    for category, path in _residual_files(job_kind, job_id):
        _add(category, path, canonical=False)
    return entries


def _rel(path: Path) -> str:
    """相对数据目录的**词法**路径：绝不 resolve（那会跟随符号链接，把待删条目
    伪装成链接目标的路径，进而误删锁定对象）。"""
    try:
        base = os.path.abspath(str(config.settings.data_dir))
        return os.path.relpath(os.path.abspath(str(path)), base)
    except OSError:
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
    """计算清理预览：只读取作业元数据与文件 stat，不读取任何文件内容。

    评估时间默认（且通常应当）为服务当前时间；调用方显式传入的 ``now`` 必须在
    时钟偏差容限内，否则抛 :class:`InvalidNowError`（由接口层转 400）。
    """
    current = validate_now(now) or _now()
    kinds = job_kinds or JOB_KINDS
    blocked = {"locked": 0, "retained": 0, "running": 0, "permanent": 0}
    items: list[PreviewItem] = []

    # 与清理评估同一时间基准：先把已到期但未标记的锁统一置为失效
    db.expire_due_locks(to_iso(current))

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
        files = _existing_file_entries(db, job_kind, job_id)
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
            bytes_total=sum(f.bytes for f in files if f.status == "present"),
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


def _file_fingerprint(item: PreviewItem) -> list[list[Any]]:
    # 文件状态（present/missing）与注记也进入指纹：文件从缺失变为现存即目标变化
    return [[f.category, f.path, f.bytes, f.status, f.note or ""]
            for f in sorted(item.files, key=lambda f: f.path)]


def compute_fingerprint(items: list[PreviewItem]) -> str:
    """目标指纹：作业三元组 + 文件(类别,路径,大小,状态) 的规范化 SHA-256（不读内容）。"""
    payload = [
        [i.job_kind, i.job_id, i.terminal_status, str(i.needs_review).lower(),
         i.completed_at, _file_fingerprint(i)]
        for i in items
    ]
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ---------- 安全删除 ----------


def _parent_components_safe(path: Path, roots: list[Path]) -> bool:
    """路径上任一级都不得是符号链接；realpath 必须仍在限定目录内。"""
    if not _is_within_roots(path, roots):
        return False
    parent = path.parent
    data_root = config.settings.data_dir.resolve()
    cur = parent
    while True:
        if cur.is_symlink():
            return False
        if cur == data_root or cur.parent == cur:
            break
        cur = cur.parent
    return True


def _safe_remove(path: Path, *, roots: list[Path]) -> str:
    """删除单个普通文件；返回 outcome 标签。

    * ``deleted``：已删除；``missing``：原本就不存在（幂等）；
    * 路径本身或任一级父目录是符号链接、realpath 越出限定数据目录时
      抛 :class:`UnsafePathError`，绝不跟随链接（链接目标可能属于另一把保留锁
      保护的作业）。
    """
    if path.is_symlink():
        raise UnsafePathError("symlink")
    if not path.exists():
        return "missing"
    if not _parent_components_safe(path, roots):
        raise UnsafePathError("out_of_tree")
    os.unlink(path)
    return "deleted"


def _walk_plain(root: Path, roots: list[Path]):
    """不跟随符号链接的深度优先遍历，产出 (child, 相对根的 PurePosix 风格路径)。

    遇到符号链接（含指向目录的链接）只作为叶子上报，绝不进入其目标。
    """
    results: list[tuple[Path, str]] = []

    def _scan(directory: Path, prefix: str) -> None:
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except OSError:
            return
        for entry in sorted(entries, key=lambda e: e.name):
            child = Path(entry.path)
            rel = f"{prefix}{entry.name}" if not prefix else f"{prefix}/{entry.name}"
            if entry.is_symlink():
                results.append((child, rel))
                continue
            if not _is_within_roots(child, roots):
                results.append((child, rel))
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir:
                _scan(child, rel)
            else:
                results.append((child, rel))

    _scan(root, "")
    return results


def _safe_rmtree(path: Path, *, roots: list[Path]) -> list[dict[str, Any]]:
    """安全删除诊断包暂存目录：符号链接/越界只记录不跟随，普通文件逐个删除。"""
    outcomes: list[dict[str, Any]] = []
    if not path.exists() and not path.is_symlink():
        return outcomes
    if path.is_symlink() or not _is_within_roots(path, roots):
        raise UnsafePathError("symlink" if path.is_symlink() else "out_of_tree")
    for child, rel in _walk_plain(path, roots):
        full_rel = _rel(child)
        if child.is_symlink():
            outcomes.append({
                "category": "bundle_staging", "path": full_rel,
                "outcome": "symlink_refused", "bytes": 0,
                "error": "符号链接，拒绝删除",
            })
            continue
        if not _is_within_roots(child, roots):
            outcomes.append({
                "category": "bundle_staging", "path": full_rel,
                "outcome": "path_refused", "bytes": 0,
                "error": "越界路径，拒绝删除",
            })
            continue
        try:
            st = child.stat()
            if stat.S_ISDIR(st.st_mode):
                continue
            size = st.st_size
            os.unlink(child)
            outcomes.append({
                "category": "bundle_staging", "path": full_rel,
                "outcome": "deleted", "bytes": size,
            })
        except OSError as exc:
            outcomes.append({
                "category": "bundle_staging", "path": full_rel,
                "outcome": "failed", "bytes": 0, "error": str(exc),
            })
    return outcomes


# ---------- 后台执行调度 ----------


def start_plan(
    plan_id: str, get_db: Callable[[], Database], *, retry_failed_only: bool = False
) -> int:
    """启动（或挤退旧 worker 后重启）一个计划的后台执行，返回执行代次。

    重试时先递增代次并等待旧 worker 退出，杜绝“旧快照 worker 把复位后的项目
    重新判失败”的竞争。
    """
    with _threads_lock:
        generation = _plan_generation.get(plan_id, 0) + 1
        _plan_generation[plan_id] = generation
        old = _plan_threads.get(plan_id)
    if old is not None and old.is_alive() and old is not threading.current_thread():
        old.join(timeout=30)

    def _run() -> None:
        try:
            run_cleanup_plan(
                plan_id, get_db, retry_failed_only=retry_failed_only,
                generation=generation,
            )
        except Exception:
            # 计划保持 running/pending，重启或重试时继续
            pass
        finally:
            with _threads_lock:
                if _plan_threads.get(plan_id) is thread:
                    _plan_threads.pop(plan_id, None)

    thread = threading.Thread(target=_run, name=f"cleanup-plan-{plan_id}", daemon=True)
    with _threads_lock:
        _plan_threads[plan_id] = thread
    thread.start()
    return generation


def _rmtree_checked(root: Path, roots: list[Path]) -> None:
    """预扫描已确认无符号链接/越界路径后，删除普通文件与空目录（不跟随链接）。"""
    if root.is_symlink() or not root.exists() or not _is_within_roots(root, roots):
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [
            d for d in dirnames if not (dp / d).is_symlink()
            and _is_within_roots(dp / d, roots)
        ]
        for name in filenames:
            fp = dp / name
            if not fp.is_symlink():
                try:
                    fp.unlink()
                except OSError:
                    pass
        for d in dirnames:
            try:
                (dp / d).rmdir()
            except OSError:
                pass
    try:
        root.rmdir()
    except OSError:
        pass


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
    planned_status: str, planned_review: bool,
    lock_now: datetime, retention_now: datetime,
) -> tuple[bool, str | None]:
    """执行前的逐作业复核（目标变化的最后一道防线）：

    * 作业必须仍存在、仍处于计划时的终态（运行中作业不得删除）；
    * 生效中的保留锁不得删除（按**服务墙钟时间**判定，安全方向）；
    * 按**当前**策略与终态/复核位重新解析期限，已不满足过期条件不得删除。
      期限复核沿用预览时的同一评估时刻 ``retention_now``，保证“预览入选 ⇒
      守卫通过”，不会因秒级时钟走动产生 partial/guard_refused。
    """
    if active_lock(db, job_kind, job_id, lock_now) is not None:
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
        if retention_now < deadline:
            return False, "保留期限尚未届满"
    return True, None


def _prescan_unsafe(planned: list[dict[str, Any]], roots: list[Path]
                    ) -> list[dict[str, Any]]:
    """删除前的整体安全预扫描：返回所有不安全条目（不删除任何文件）。

    任意一个规范文件是符号链接/越界路径，或暂存目录内含符号链接/越界路径，
    整个作业项都必须在删除前失败——否则可能误删链接目标（它也许正被另一把
    保留锁保护）。
    """
    unsafe: list[dict[str, Any]] = []
    for entry in planned:
        category = entry["category"]
        rel = entry["path"]
        path = config.settings.data_dir / rel.rstrip("/")
        if category == "bundle_staging":
            if path.is_symlink():
                unsafe.append({"category": category, "path": rel,
                               "outcome": "symlink_refused", "bytes": 0,
                               "error": "暂存目录本身是符号链接，拒绝删除"})
                continue
            if not path.exists():
                continue
            if not _is_within_roots(path, roots):
                unsafe.append({"category": category, "path": rel,
                               "outcome": "path_refused", "bytes": 0,
                               "error": "越界路径，拒绝删除"})
                continue
            for child, child_rel in _walk_plain(path, roots):
                full_rel = _rel(child)
                if child.is_symlink():
                    unsafe.append({"category": category, "path": full_rel,
                                   "outcome": "symlink_refused", "bytes": 0,
                                   "error": "暂存目录内含符号链接，拒绝删除"})
                elif not _is_within_roots(child, roots):
                    unsafe.append({"category": category, "path": full_rel,
                                   "outcome": "path_refused", "bytes": 0,
                                   "error": "暂存目录内含越界路径，拒绝删除"})
            continue
        if path.is_symlink():
            unsafe.append({"category": category, "path": rel,
                           "outcome": "symlink_refused", "bytes": 0,
                           "error": "符号链接，拒绝删除（不跟随到目标）"})
        elif path.exists() and not _parent_components_safe(path, roots):
            unsafe.append({"category": category, "path": rel,
                           "outcome": "path_refused", "bytes": 0,
                           "error": "越界路径或父路径含符号链接，拒绝删除"})
    return unsafe


def _delete_item(
    db: Database, item_row: sqlite3.Row, *,
    lock_now: datetime, retention_now: datetime,
) -> tuple[str, list[dict[str, Any]], int, int]:
    """删除单个作业项；返回 (status, outcomes, processed_count, deleted_bytes)。

    status=done 时文件与数据库记录均已处理；failed 时记录原样保留供重试。
    """
    job_kind = item_row["job_kind"]
    job_id = item_row["job_id"]
    planned = json.loads(item_row["planned_files_json"] or "[]")
    roots = _allowed_roots()

    ok, reason = _guards_pass(
        db, job_kind=job_kind, job_id=job_id,
        planned_status=item_row["terminal_status"],
        planned_review=bool(item_row["needs_review"]),
        lock_now=lock_now, retention_now=retention_now,
    )
    if not ok:
        return "failed", [{
            "category": "guard", "path": None, "outcome": "guard_refused",
            "bytes": 0, "error": reason,
        }], 0, 0

    # 1) 整体预扫描：任何符号链接/越界目标都在删除任何文件之前失败
    unsafe = _prescan_unsafe(planned, roots)
    if unsafe:
        outcomes = [{
            "category": "guard", "path": None, "outcome": "unsafe_target_refused",
            "bytes": 0,
            "error": "存在符号链接或越界路径，整个作业项拒绝删除（链接目标未被触碰）",
        }] + unsafe
        return "failed", outcomes, 0, 0

    # 2) 预扫描通过后逐项删除（此时不可能再遇到符号链接；缺失按已删记录）
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
            sub = _safe_rmtree(path, roots=roots)
            if not sub:
                # 空暂存目录：删除目录本身并记 deleted
                try:
                    path.rmdir()
                    outcomes.append({"category": category, "path": rel,
                                     "outcome": "deleted", "bytes": 0})
                except OSError as exc:
                    failed = True
                    outcomes.append({"category": category, "path": rel,
                                     "outcome": "failed", "bytes": 0,
                                     "error": str(exc)})
            else:
                outcomes.extend(sub)
                deleted_bytes += sum(
                    o.get("bytes", 0) for o in sub if o["outcome"] == "deleted"
                )
                if any(o["outcome"] in ("symlink_refused", "path_refused", "failed")
                       for o in sub):
                    failed = True
                else:
                    _rmtree_checked(path, roots)
            continue

        expected_status = entry.get("status", "present")
        try:
            size = path.stat().st_size if path.exists() else 0
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
        elif outcome == "missing" and expected_status == "present":
            # 规范集合中的文件缺失：明确记录（结果非空，可查询、可审计）
            outcome = "missing"
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
    generation: int | None = None,
) -> CleanupPlanModel:
    """执行（或继续/重试）一个已持久化的清理计划。进程内串行。

    安全守卫（保留锁、运行中、保留期限）一律按**服务当前时间**复核，与锁状态
    查询、预览评估使用同一时间基准；调用方无法用未来时间让作业提前可删。
    ``generation`` 用于让重试/恢复启动的新执行挤退陈旧 worker。
    """
    with _cleanup_run_lock:
        db = get_db()
        # 已被更新一代执行取代的陈旧 worker 直接退出（避免它把复位后的项目
        # 按旧快照重新判失败）
        if generation is not None and _plan_generation.get(plan_id, 0) > generation:
            return _plan_model(db, db.get_cleanup_plan_row(plan_id))
        row = db.get_cleanup_plan_row(plan_id)
        if row is None:
            raise KeyError(plan_id)
        if row["status"] == "succeeded":
            return _plan_model(db, row)
        current = _now(now)
        # 锁过期失效在删除前统一处理一次
        db.expire_due_locks(to_iso(current))
        db.mark_cleanup_plan_running(plan_id)
        db.add_retention_audit(
            "cleanup.plan.retried" if retry_failed_only else "cleanup.plan.started",
            plan_id=plan_id,
        )

        # 期限复核时刻：首轮执行沿用提交预览时的评估时刻（保证预览入选⇒守卫通过）；
        # 重试/重启续跑按当前墙钟时间重新复核。保留锁/运行中检查始终用墙钟时间。
        if retry_failed_only or row["started_at"]:
            retention_now = current
        else:
            submitted = json.loads(row["submitted_preview_json"] or "{}")
            retention_now = parse_iso(submitted.get("generated_at")) or current

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
                db, item_row, lock_now=current, retention_now=retention_now,
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
        "generated_at": preview["generated_at"],
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
